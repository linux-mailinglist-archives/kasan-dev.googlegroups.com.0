Return-Path: <kasan-dev+bncBCLMXXWM5YBBBV4SY3AAMGQEMD6JA7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 62E7AAA40E5
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 04:22:17 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-736b2a25d9fsf4584249b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 19:22:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745979735; cv=pass;
        d=google.com; s=arc-20240605;
        b=cjvxM3sz4ORJ4CeYyt1MuKFtjePGTEMnuTadnakdYBFwAOVVHgvJpcxNkKoJDsl7SP
         NmTHavmoZZc41vxcTPBCn5aNjoHHCLTMbDIwEc3f/DeqUaou4keH99Uee/WEWs5ULMsd
         vky1UDnJpIJmH+JH9RIZvNI1DwUKU5wIseJ4bjlqOzxB2KD2ETtxfGmFE95Q0N1DEqOY
         6z5Lhnm/q6ZMeF+bjBfUExgp41EwFSa328cd5hRe8gbZMNkExCm2xngaConf+rRE8XqM
         WDrC+McdOFCOgQ5QP4iuCJOp43YMYhzmcllPl482QjWlifRreBZWSPGjcNpO3nD2gGyS
         vqgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ab/WRAHwvXAaS34o5zOw7R9SkRJv8XD/xK4NS/FjjRE=;
        fh=PNDG4VsTpANmMBQaXJw4rST3AaIly89T818nEZn3JuA=;
        b=hgo5HR/8bKx8bHaSbCBM8iIKWtXEy9w4By7DMSG1aXf3OXCzeDqR7z1opEGirDGYzJ
         40qFniEPbIzFNKaedL5jvYs6sY1XREmIxvYEGqRlJFuCS7prbLzjSjymo27t2brfeQMD
         I2olwfHO5+fBgMXfKA4sz3ARZdMkcqhNI7KuiL7lMsNeLGt0qZ5vs7y8o3s0/3mrml+l
         8IB5nsMelfjdsr7U2UOn2k5+ZOqEPIm0IDRr6u0vzo6XpV0M9yePToR1m+7afSUvAcHa
         0FTTxDS24+CrWYj4fmq0fjwxco0bPBPhqKqILdFFfR5nwNEMPdn/QslH7jZDFMfwmKhf
         ekhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=FuNczuK4;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745979735; x=1746584535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ab/WRAHwvXAaS34o5zOw7R9SkRJv8XD/xK4NS/FjjRE=;
        b=hxgLn+b/OLjCQnSnMImbMQ+lSmjpyxx7mfrULW4dyYerbTDXOKTOPDf9aGxujbgyhR
         tSMNBVOV/r8pTrfXV7MHAoOVM+jj5x4vudW3J/akyFvbzOOro8uxDspC2lFCfIXfzDhQ
         k0suOH/RQmAon8QcmWUtLrEwXXw++ZExb906rlhsQ4sw+1+pqA5JJmFYrSMD8oSauyEc
         p+pi2o1KYVrZjEjEoieIh0PDhasrtVMbdBz6t5E0aqPa0mscmzDsOjV/qT0K5Hzf9Bh0
         E5eg3898iQnbsDHsiL9DkQfgBDi178/FDrDyPqGR3GX/03FG7PzkdJYIBaWuLkqvW9g1
         qb+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745979735; x=1746584535;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ab/WRAHwvXAaS34o5zOw7R9SkRJv8XD/xK4NS/FjjRE=;
        b=knvk/VGFLxLIywoSNKD4ViWcXshObTqvENwejKA950bV5pS+PBGYL8qQokjgkiI2+F
         4G3G+1J3IbjvAVjd++FlZ9xaKFYWp9VH/tsIjA+u7PVvrxWC/aXct4oKmsalH0av7QYB
         p6kxBjL3uRsOaNN7aM6JJKtxZTRi4tTkURz7XnaEoaGL3uGpWjPK4RGUqDDg/lhdKJIO
         nEQFsPzU2RTmV9gJauIC/iR845x9czCNIXNz5Fxw4fh7G1YuOiWFHdQiWaFbGNcp23lz
         MzXyrCI/zaXrGPA70K17PguAwlmSPu421cH33Vpsz07ZOtxCHkM5nXm1WFcP5lAY5nU0
         TQOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrYlsITBCB157N8Mg/qqZGeig2bwpUhFxOwL+8zMPS5+pdW5kASVD/gdf4TPzVxcGDfV4hOg==@lfdr.de
X-Gm-Message-State: AOJu0YymDdpMO6tybhVKI7t+TrJCuTvNLIoqH0QQr1dPKJvVwZAW1ZrD
	T6EdePNL01OnhXL3ErdcwGJIz4d/Ivvf44UOyCBANJ8qZYc0cRUj
X-Google-Smtp-Source: AGHT+IF1aNJkfm2buMkON75zXpU+GGOtzFpjiCUa3JZeKh+pG08VsWXkdL+mHUCePe3S6UuLqRAI5w==
X-Received: by 2002:a05:6a00:3d46:b0:736:4e0a:7e82 with SMTP id d2e1a72fcca58-740389aebfemr2072377b3a.10.1745979735338;
        Tue, 29 Apr 2025 19:22:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEFBqa+7nQTKTJRokIugxqwJK84yjYbdcEZUP8yrk7PkA==
Received: by 2002:a05:6a00:4602:b0:728:f8a6:8599 with SMTP id
 d2e1a72fcca58-73e219dd661ls5222807b3a.0.-pod-prod-09-us; Tue, 29 Apr 2025
 19:22:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoQbr8UVFLUq+hOicCY5944jJfofqdv5GviKx7EzLtIgatKMAwt7y4C2P6jfbgDozhSmrJBzNK+aE=@googlegroups.com
X-Received: by 2002:a05:6a20:9f9a:b0:1f5:7ba7:69d7 with SMTP id adf61e73a8af0-20a87251a5emr1866376637.3.1745979734028;
        Tue, 29 Apr 2025 19:22:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745979734; cv=none;
        d=google.com; s=arc-20240605;
        b=O6mmrAiQwcIp7CVXeNZM4sbGoLrc0bWT6hB6foxg/dsj6pD/HFGYVMM0KAVXO8WKXz
         4lFZnE3Pu8plz89VXE310fSvuTSdc5QJNqGsZ8BgEhqI08SFuod4Est2CXtPe7ZlNjO6
         3uFqpY5iKz03znfCUcoYM1f7ol+iOHcaUoomd3k5qfO0uG3Vlm8IRdcZFmxN7a+djmbH
         igvpPr62u8u62a2NLoENKQ3czp/3L3mH6unVC+ID01aEfma50KcHmldvMiaBkfdmmlh0
         Y3QJC7NFTV9cBjjfK+vsFZLcP3wc1izR9kJMjqMTfX16tJAc7aUs7L8wEu7+C0DanTAG
         sUUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+dNA4WT0YksUqtsfniJBr4Yd4CV3UaXPulrWB2ZFegk=;
        fh=OwKhG8UGzWgJpwlfldbq75lXbIYcbWbbr20b4dKRzcs=;
        b=YAcEj4tk0FBQowUMKhSqPv2mr4m/XcKEJC3vhmshWJ9ZY5Vi+wvTLg8XKAO7Hx5V7O
         QAt9b1DbDonP5AZbZgnYmtKpDIlKmVWnSuZMEApzJ9Ta+Pcuc+s0z+cAtibOhm2hq4Ln
         dJlOlSMHftcPuSwLsL+RF19lKPNr3H5orqiYnVSk3sEiuo6KaLKnI7j/GxL1LrigGxPB
         3hiBJKKe+LAiY3f36lYQS91tyLm/kLV0DP2xh0BZXD4TfFgwDn6FUp2GZNsMw94W8CWN
         8tDC76sVMGEy5ksGnCALAad5yfGZdEj/vnru54fTvgq3jE7lwMhpjiFz9QeOOEBwKUia
         RQZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=FuNczuK4;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-740398fd889si30631b3a.1.2025.04.29.19.22.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Apr 2025 19:22:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53TLaiJX001229;
	Wed, 30 Apr 2025 02:21:59 GMT
Received: from nasanppmta05.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 46b6u9rh4a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 30 Apr 2025 02:21:59 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA05.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 53U2Lw5G002345
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 30 Apr 2025 02:21:58 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Tue, 29 Apr 2025 19:21:55 -0700
Date: Wed, 30 Apr 2025 10:21:52 +0800
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Alexander Potapenko <glider@google.com>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        Aleksandr
 Nogikh <nogikh@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Borislav
 Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Dmitry
 Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
        Josh Poimboeuf
	<jpoimboe@kernel.org>, Marco Elver <elver@google.com>,
        Peter Zijlstra
	<peterz@infradead.org>,
        Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
Message-ID: <aBGJQF8aMfWmz7RI@hu-jiangenj-sha.qualcomm.com>
References: <20250416085446.480069-1-glider@google.com>
 <20250416085446.480069-6-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250416085446.480069-6-glider@google.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: sRcwMwhFzls9v268hynIGxnUi3FpBTDG
X-Proofpoint-ORIG-GUID: sRcwMwhFzls9v268hynIGxnUi3FpBTDG
X-Authority-Analysis: v=2.4 cv=UZZRSLSN c=1 sm=1 tr=0 ts=68118947 cx=c_pps a=JYp8KDb2vCoCEuGobkYCKw==:117 a=JYp8KDb2vCoCEuGobkYCKw==:17 a=GEpy-HfZoHoA:10 a=kj9zAlcOel0A:10 a=XR8D0OoHHMoA:10 a=1XWaLZrsAAAA:8 a=DSPBSGmzSnmKTek9qQoA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNDMwMDAxNSBTYWx0ZWRfX8FsQUMQu4Cdj WZksUnmeu33OnCqdeafWI9Qonr+kiDkrgFvWTF1IliT8gMyQcAuKO+wVhj5V1OuvjQAqEqFkOpt vMS2S0cg+9f95gR5BV+YKwAKRcVZgewobzs3KIBPGsYKy9YtqqCv4J1TBPSbKNkeJ5NiX+x1bFe
 tpedlvGE29hMTGLvPG9MKXGK7qAc2s4gdXJs9Mi2L3tgYBXKbdeGumN4FzK6z8Tq6H0vTvjHk0u BNAsCc3pTaN7wtGhgXF9lr300WAzKwbiOfMLlUX4vh88sUHLXrcsN2R8+3yTusOBdiMpT0Hhg9A zCD1GB0P6ReoEEYARLduu1CgFk5FzV8PqYIacLRXdrx7PgtlQDP91gmKqIbxaqW8kqLV8v4ARps
 7gdvJ/PpFWdmdCZ6QhxLczAJs1yU+D7A+fM5xbSiKh0PfZBXWlq40ZfUe8HvZCLqjnlfsagN
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-04-29_08,2025-04-24_02,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 adultscore=0
 mlxlogscore=784 spamscore=0 priorityscore=1501 impostorscore=0 mlxscore=0
 malwarescore=0 suspectscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2504300015
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=FuNczuK4;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, Apr 16, 2025 at 10:54:43AM +0200, Alexander Potapenko wrote:
> ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> in the presence of CONFIG_KCOV_ENABLE_GUARDS.
> 
> The buffer shared with the userspace is divided in two parts, one holding
> a bitmap, and the other one being the trace. The single parameter of
> ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> bitmap.
> 
> Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> pointer to a unique guard variable. Upon the first call of each hook,
> the guard variable is initialized with a unique integer, which is used to
> map those hooks to bits in the bitmap. In the new coverage collection mode,
> the kernel first checks whether the bit corresponding to a particular hook
> is set, and then, if it is not, the PC is written into the trace buffer,
> and the bit is set.
> 
> Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENABLE)
> returns -ENOTSUPP, which is consistent with the existing kcov code.
> 
> Also update the documentation.
> 
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  Documentation/dev-tools/kcov.rst |  43 +++++++++++
>  include/linux/kcov-state.h       |   8 ++
>  include/linux/kcov.h             |   2 +
>  include/uapi/linux/kcov.h        |   1 +
>  kernel/kcov.c                    | 129 +++++++++++++++++++++++++++----
>  5 files changed, 170 insertions(+), 13 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 6611434e2dd24..271260642d1a6 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -137,6 +137,49 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
>  processes only need to enable coverage (it gets disabled automatically when
>  a thread exits).
>  
> +Unique coverage collection
> +---------------------------
> +
> +Instead of collecting raw PCs, KCOV can deduplicate them on the fly.
> +This mode is enabled by the ``KCOV_UNIQUE_ENABLE`` ioctl (only available if
> +``CONFIG_KCOV_ENABLE_GUARDS`` is on).
> +
> +.. code-block:: c
> +
> +	/* Same includes and defines as above. */
> +	#define KCOV_UNIQUE_ENABLE		_IOW('c', 103, unsigned long)
in kcov.h it was defined was _IOR, but _IOW here,
#define KCOV_UNIQUE_ENABLE             _IOR('c', 103, unsigned long)
> +	#define BITMAP_SIZE			(4<<10)
> +
> +	/* Instead of KCOV_ENABLE, enable unique coverage collection. */
> +	if (ioctl(fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE))
> +		perror("ioctl"), exit(1);
> +	/* Reset the coverage from the tail of the ioctl() call. */
> +	__atomic_store_n(&cover[BITMAP_SIZE], 0, __ATOMIC_RELAXED);
> +	memset(cover, 0, BITMAP_SIZE * sizeof(unsigned long));
> +
> +	/* Call the target syscall call. */
> +	/* ... */
> +
> +	/* Read the number of collected PCs. */
> +	n = __atomic_load_n(&cover[BITMAP_SIZE], __ATOMIC_RELAXED);
> +	/* Disable the coverage collection. */
> +	if (ioctl(fd, KCOV_DISABLE, 0))
> +		perror("ioctl"), exit(1);
> +
> +Calling ``ioctl(fd, KCOV_UNIQUE_ENABLE, bitmap_size)`` carves out ``bitmap_size``
> +words from those allocated by ``KCOV_INIT_TRACE`` to keep an opaque bitmap that
> +prevents the kernel from storing the same PC twice. The remaining part of the
> +trace is used to collect PCs, like in other modes (this part must contain at
> +least two words, like when collecting non-unique PCs).
> +
> +The mapping between a PC and its position in the bitmap is persistent during the
> +kernel lifetime, so it is possible for the callers to directly use the bitmap
> +contents as a coverage signal (like when fuzzing userspace with AFL).
> +
> +In order to reset the coverage between the runs, the user needs to rewind the
> +trace (by writing 0 into the first word past ``bitmap_size``) and wipe the whole
> +bitmap.
> +
>  Comparison operands collection
>  ------------------------------
>  
> diff --git a/include/linux/kcov-state.h b/include/linux/kcov-state.h
> index 6e576173fd442..26e275fe90684 100644
> --- a/include/linux/kcov-state.h
> +++ b/include/linux/kcov-state.h
> @@ -26,6 +26,14 @@ struct kcov_state {
>  		/* Buffer for coverage collection, shared with the userspace. */
>  		unsigned long *trace;
>  
> +		/* Size of the bitmap (in bits). */
> +		unsigned int bitmap_size;
> +		/*
> +		 * Bitmap for coverage deduplication, shared with the
> +		 * userspace.
> +		 */
> +		unsigned long *bitmap;
> +
>  		/*
>  		 * KCOV sequence number: incremented each time kcov is
>  		 * reenabled, used by kcov_remote_stop(), see the comment there.
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 7ec2669362fd1..41eebcd3ab335 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -10,6 +10,7 @@ struct task_struct;
>  #ifdef CONFIG_KCOV
>  
>  enum kcov_mode {
> +	KCOV_MODE_INVALID = -1,
>  	/* Coverage collection is not enabled yet. */
>  	KCOV_MODE_DISABLED = 0,
>  	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
> @@ -23,6 +24,7 @@ enum kcov_mode {
>  	KCOV_MODE_TRACE_CMP = 3,
>  	/* The process owns a KCOV remote reference. */
>  	KCOV_MODE_REMOTE = 4,
> +	KCOV_MODE_TRACE_UNIQUE_PC = 5,
>  };
>  
>  #define KCOV_IN_CTXSW (1 << 30)
> diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> index ed95dba9fa37e..fe1695ddf8a06 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -22,6 +22,7 @@ struct kcov_remote_arg {
>  #define KCOV_ENABLE			_IO('c', 100)
>  #define KCOV_DISABLE			_IO('c', 101)
>  #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
> +#define KCOV_UNIQUE_ENABLE		_IOR('c', 103, unsigned long)
>  
>  enum {
>  	/*
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 7b726fd761c1b..dea25c8a53b52 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -29,6 +29,10 @@
>  
>  #include <asm/setup.h>
>  
> +#ifdef CONFIG_KCOV_ENABLE_GUARDS
> +atomic_t kcov_guard_max_index = ATOMIC_INIT(1);
> +#endif
> +
>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
>  
>  /* Number of 64-bit words written per one comparison: */
> @@ -161,8 +165,7 @@ static __always_inline bool in_softirq_really(void)
>  	return in_serving_softirq() && !in_hardirq() && !in_nmi();
>  }
>  
> -static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
> -				    struct task_struct *t)
> +static notrace enum kcov_mode get_kcov_mode(struct task_struct *t)
>  {
>  	unsigned int mode;
>  
> @@ -172,7 +175,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
>  	 * coverage collection section in a softirq.
>  	 */
>  	if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
> -		return false;
> +		return KCOV_MODE_INVALID;
>  	mode = READ_ONCE(t->kcov_state.mode);
>  	/*
>  	 * There is some code that runs in interrupts but for which
> @@ -182,7 +185,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
>  	 * kcov_start().
>  	 */
>  	barrier();
> -	return mode == needed_mode;
> +	return mode;
>  }
>  
>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> @@ -201,7 +204,7 @@ static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
>  
>  	if (likely(pos < size)) {
>  		/*
> -		 * Some early interrupt code could bypass check_kcov_mode() check
> +		 * Some early interrupt code could bypass get_kcov_mode() check
>  		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
>  		 * raised between writing pc and updating pos, the pc could be
>  		 * overitten by the recursive __sanitizer_cov_trace_pc().
> @@ -220,7 +223,7 @@ static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
>  #ifndef CONFIG_KCOV_ENABLE_GUARDS
>  void notrace __sanitizer_cov_trace_pc(void)
>  {
> -	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +	if (get_kcov_mode(current) != KCOV_MODE_TRACE_PC)
>  		return;
>  
>  	sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> @@ -229,14 +232,73 @@ void notrace __sanitizer_cov_trace_pc(void)
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>  #else
> +
> +DEFINE_PER_CPU(u32, saved_index);
> +/*
> + * Assign an index to a guard variable that does not have one yet.
> + * For an unlikely case of a race with another task executing the same basic
> + * block, we store the unused index in a per-cpu variable.
> + * In an even less likely case the current task may lose a race and get
> + * rescheduled onto a CPU that already has a saved index, discarding that index.
> + * This will result in an unused hole in the bitmap, but such events should have
> + * minor impact on the overall memory consumption.
> + */
> +static __always_inline u32 init_pc_guard(u32 *guard)
> +{
> +	/* If the current CPU has a saved free index, use it. */
> +	u32 index = this_cpu_xchg(saved_index, 0);
> +	u32 old_guard;
> +
> +	if (likely(!index))
> +		/*
> +		 * Allocate a new index. No overflow is possible, because 2**32
> +		 * unique basic blocks will take more space than the max size
> +		 * of the kernel text segment.
> +		 */
> +		index = atomic_inc_return(&kcov_guard_max_index) - 1;
> +
> +	/*
> +	 * Make sure another task is not initializing the same guard
> +	 * concurrently.
> +	 */
> +	old_guard = cmpxchg(guard, 0, index);
> +	if (unlikely(old_guard)) {
> +		/* We lost the race, save the index for future use. */
> +		this_cpu_write(saved_index, index);
> +		return old_guard;
> +	}
> +	return index;
> +}
> +
>  void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
>  {
> -	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> -		return;
> +	u32 pc_index;
> +	enum kcov_mode mode = get_kcov_mode(current);
>  
> -	sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> -				       current->kcov_state.s.trace_size,
> -				       canonicalize_ip(_RET_IP_));
> +	switch (mode) {
> +	case KCOV_MODE_TRACE_UNIQUE_PC:
> +		pc_index = READ_ONCE(*guard);
> +		if (unlikely(!pc_index))
> +			pc_index = init_pc_guard(guard);
> +
> +		/*
> +		 * Use the bitmap for coverage deduplication. We assume both
> +		 * s.bitmap and s.trace are non-NULL.
> +		 */
> +		if (likely(pc_index < current->kcov_state.s.bitmap_size))
> +			if (test_and_set_bit(pc_index,
> +					     current->kcov_state.s.bitmap))
> +				return;
> +		/* If the PC is new, write it to the trace. */
> +		fallthrough;
> +	case KCOV_MODE_TRACE_PC:
> +		sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> +					       current->kcov_state.s.trace_size,
> +					       canonicalize_ip(_RET_IP_));
> +		break;
> +	default:
> +		return;
> +	}
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
>  
> @@ -255,7 +317,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>  	u64 *trace;
>  
>  	t = current;
> -	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> +	if (get_kcov_mode(t) != KCOV_MODE_TRACE_CMP)
>  		return;
>  
>  	ip = canonicalize_ip(ip);
> @@ -374,7 +436,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
>  	/* Cache in task struct for performance. */
>  	t->kcov_state.s = state->s;
>  	barrier();
> -	/* See comment in check_kcov_mode(). */
> +	/* See comment in get_kcov_mode(). */
>  	WRITE_ONCE(t->kcov_state.mode, state->mode);
>  }
>  
> @@ -408,6 +470,10 @@ static void kcov_reset(struct kcov *kcov)
>  	kcov->state.mode = KCOV_MODE_INIT;
>  	kcov->remote = false;
>  	kcov->remote_size = 0;
> +	kcov->state.s.trace = kcov->state.s.area;
> +	kcov->state.s.trace_size = kcov->state.s.size;
> +	kcov->state.s.bitmap = NULL;
> +	kcov->state.s.bitmap_size = 0;
>  	kcov->state.s.sequence++;
>  }
>  
> @@ -594,6 +660,41 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
>  	return false;
>  }
>  
> +static long kcov_handle_unique_enable(struct kcov *kcov,
> +				      unsigned long bitmap_words)
> +{
> +	struct task_struct *t = current;
> +
> +	if (!IS_ENABLED(CONFIG_KCOV_ENABLE_GUARDS))
> +		return -ENOTSUPP;
> +	if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
> +		return -EINVAL;
> +	if (kcov->t != NULL || t->kcov != NULL)
> +		return -EBUSY;
> +
> +	/*
> +	 * Cannot use zero-sized bitmap, also the bitmap must leave at least two
> +	 * words for the trace.
> +	 */
> +	if ((!bitmap_words) || (bitmap_words >= (kcov->state.s.size - 1)))
> +		return -EINVAL;
> +
> +	kcov->state.s.bitmap_size = bitmap_words * sizeof(unsigned long) * 8;
> +	kcov->state.s.bitmap = kcov->state.s.area;
> +	kcov->state.s.trace_size = kcov->state.s.size - bitmap_words;
> +	kcov->state.s.trace =
> +		((unsigned long *)kcov->state.s.area + bitmap_words);
> +
> +	kcov_fault_in_area(kcov);
> +	kcov->state.mode = KCOV_MODE_TRACE_UNIQUE_PC;
> +	kcov_start(t, kcov, &kcov->state);
> +	kcov->t = t;
> +	/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
> +	kcov_get(kcov);
> +
> +	return 0;
> +}
> +
>  static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>  			     unsigned long arg)
>  {
> @@ -627,6 +728,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>  		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>  		kcov_get(kcov);
>  		return 0;
> +	case KCOV_UNIQUE_ENABLE:
> +		return kcov_handle_unique_enable(kcov, arg);
>  	case KCOV_DISABLE:
>  		/* Disable coverage for the current task. */
>  		unused = arg;
> -- 
> 2.49.0.604.gff1f9ca942-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBGJQF8aMfWmz7RI%40hu-jiangenj-sha.qualcomm.com.
