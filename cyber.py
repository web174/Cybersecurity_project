import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import seaborn as sns

# Page configuration
st.set_page_config(page_title="Cybersecurity Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ **Cybersecurity Analytics Dashboard**")
st.markdown(" **Upload CSV → Instant Pro Analysis!**")

# File uploader
uploaded_file = st.file_uploader("📁 Choose CSV file", type="csv")

if uploaded_file is not None:
    @st.cache_data
    def safe_load_data(file):
        try:
            # Read raw to diagnose structure
            raw_content = file.read().decode('utf-8')
            file.seek(0)  # Reset file pointer
            
            # Try standard CSV first
            df = pd.read_csv(file)
            
            # **DIAGNOSIS**: Show raw structure
            st.info(f"📊 Raw shape: {df.shape}")
            st.info(f"🔍 Columns: {list(df.columns)}")
            st.info(f"📝 First row preview: {str(df.iloc[0].values[:5])}...")
            
            # **SAFE COLUMN NORMALIZATION**
            df.columns = [str(col).strip().lower().replace(' ', '').replace('.', '') for col in df.columns]
            
            # **FIND NUMERIC COLUMNS** (bytesin/bytesout pattern)
            numeric_cols = []
            for col in df.columns:
                try:
                    pd.to_numeric(df[col], errors='raise')
                    numeric_cols.append(col)
                except:
                    pass
            
            # **FIND RELEVANT COLUMNS**
            ip_cols = [col for col in df.columns if 'ip' in col]
            country_cols = [col for col in df.columns if 'country' in col]
            time_cols = [col for col in df.columns if 'time' in col]
            
            st.success(f"✅ Numeric cols found: {numeric_cols[:3]}")
            st.success(f"✅ IP cols: {ip_cols}, Country: {country_cols}")
            
            # **SMART ANOMALY DETECTION**
            if len(numeric_cols) > 0:
                bytes_col = numeric_cols[0]
                threshold = df[bytes_col].quantile(0.95)
                df['anomaly'] = np.where(df[bytes_col] > threshold, 'Suspicious', 'Normal')
            else:
                df['anomaly'] = 'Normal'  # Fallback
            
            return df
            
        except Exception as e:
            st.error(f"❌ Load error: {e}")
            # **FALLBACK: Parse as single column**
            file.seek(0)
            raw = file.read().decode('utf-8')
            lines = raw.strip().split('\n')
            
            data = []
            for line in lines[1:100]:  # First 100 lines
                if len(line) > 50:
                    data.append([line[:20], line[20:40], len(line), 'Suspicious'])
            
            df = pd.DataFrame(data, columns=['src', 'data', 'length', 'anomaly'])
            return df

    df = safe_load_data(uploaded_file)
    
    # **SAFE DATA PREVIEW** - Only show existing columns
    st.subheader("📋 Data Preview")
    preview_cols = ['anomaly']
    if len(df.columns) > 1:
        preview_cols += [col for col in ['srcip', 'srcipcountrycode', 'bytesin', 'bytesout'] if col in df.columns][:3]
    
    st.dataframe(df[preview_cols].head(10))
    
    # **SUMMARY METRICS** - Safe version
    st.subheader("📊 Key Metrics")
    col1, col2, col3 = st.columns(3)
    
    col1.metric("Total Records", len(df))
    
    susp_count = len(df[df['anomaly'] == 'Suspicious'])
    col2.metric("Suspicious", susp_count, f"{susp_count/len(df)*100:.1f}%")
    
    # Find any numeric column for avg
    num_cols = df.select_dtypes(include=[np.number]).columns
    if len(num_cols) > 0:
        col3.metric("Avg Value", f"{df[num_cols[0]].mean():,.0f}")
    
    # **INTERACTIVE CHARTS** - Only if data exists
    col1, col2 = st.columns(2)
    
    with col1:
        # Always works pie chart
        anomaly_counts = df['anomaly'].value_counts()
        fig_pie = px.pie(values=anomaly_counts.values, names=anomaly_counts.index, 
                        title="Traffic Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Country chart if exists
        country_col = next((col for col in ['srcipcountrycode', 'country'] if col in df.columns), None)
        if country_col:
            top_countries = df[df['anomaly']=='Suspicious'][country_col].value_counts().head(8)
            fig_bar = px.bar(x=top_countries.index, y=top_countries.values, 
                           title=f"Top {country_col.title()}")
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("✅ Add country column for geo-analysis")
    
    # **DISTRIBUTION PLOT** - Safe version
    st.subheader("📈 Data Distribution")
    num_cols = df.select_dtypes(include=[np.number]).columns
    if len(num_cols) > 0:
        selected_col = st.selectbox("Choose column for distribution", num_cols)
        
        fig, ax = plt.subplots(figsize=(12, 6))
        sns.histplot(data=df, x=selected_col, hue='anomaly', bins=30, kde=True, ax=ax)
        plt.title(f"{selected_col.title()} Distribution")
        plt.xticks(rotation=45)
        st.pyplot(fig)
    else:
        st.info("No numeric columns found")
    
    # **TOP ITEMS BAR CHART**
    st.subheader("🏆 Top Items")
    cat_cols = df.select_dtypes(include=['object']).columns
    if len(cat_cols) > 1:
        selected_cat = st.selectbox("Show top values of:", cat_cols)
        top_items = df[df['anomaly']=='Suspicious'][selected_cat].value_counts().head(10)
        st.bar_chart(top_items)
    
    # **SUSPICIOUS TABLE**
    st.subheader("🚨 Suspicious Records")
    susp_cols = ['anomaly'] + [col for col in df.columns if col != 'anomaly'][:5]
    st.dataframe(df[df['anomaly']=='Suspicious'][susp_cols].head(50), height=400)

else:
    st.markdown("""
    ### 🚀 **Quick Start:**
    1. Upload CSV file
    2. Auto-detects structure [file:2]
    3. Smart anomaly detection
    4. Interactive charts & insights
    
    **Works with ANY CSV** - no column names needed! 🔥
    """)

st.markdown("---")
