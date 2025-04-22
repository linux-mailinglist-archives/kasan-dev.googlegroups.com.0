Return-Path: <kasan-dev+bncBCLMXXWM5YBBB2ORTTAAMGQEXB3UWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BD2FA95D48
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 07:28:11 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3d81d99e4e6sf40844505ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 22:28:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745299690; cv=pass;
        d=google.com; s=arc-20240605;
        b=UMJz/gTRVqUj2u/rmvPIzg7fokV3/VxVnstoi+KGzGpjprLRCD2w8AMmrvsZ30zGfM
         EDl1ccaC+ZfGrI8nAPpk+EPlksKA72OJZ6fr1TUKFof56OtngbrpehBnznGqfnGYUmmz
         GWOqosQrgqKQJYyJ/z2wwEPX0E9GL26vsHkyEZKSDKJ60qkhxGk1176eSh0TshRnVFrg
         PIGEZaeEOU/tUQ1rYjBo2V8xB5WDkIcmodWW0fj1U3e8gPTOh7nBZ3UTBCKHsKT94rvJ
         NGsxgMop6UZ/jJP8CVlslGM7PVM0JhFsvJeZG0wmxkEoXCU9hbGLON0ocaVC6CvQxkx5
         4C+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s9TQbRiJMy98ffYqTKpjY3E+dGt1DgpWfOVrNVduG34=;
        fh=AlFSOjjZ9jmjBiif1Mw2ZZmv1KFMGCsDXzSJFFNSC1k=;
        b=JxlB1oi3UYzS4OsWtpoRVVtr7hgPLgYyQGPOw4a3WoUV0tDrYZvNbcqazlIMPFXOdF
         +ZGkMxiXiWf/iywbDnQrBrnZDwyNpi2ss6X3kFBxrA28AHIaKGkJOzUWW695i5hkwHaE
         2hAnO09CsrbmxeNV0zMg7nVoI0s4Rbq1CAzUE66J4MhUF66Aznop5yxZ1tQyXzP2v3Eo
         CRFTVvvv3nWJ9fVl8kUr5EyalQ4rDah+VBSNXZxOC0ECo76o785INVCdyj/CYHUnNQfX
         1YmHp1EZW8sT9NbRPuThGTl86h6rhQRvir4VJaknvjgY3TG4Ads6XyzZ0Vbg/AwNKXac
         STcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Ay1d0q7t;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745299690; x=1745904490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s9TQbRiJMy98ffYqTKpjY3E+dGt1DgpWfOVrNVduG34=;
        b=MMAhjklHHnnHSuQniZ6wV5dML8kP2KE0jXe7V1QRpwUY/jkX8QDKngk8ZurmxZ7XPx
         lwP9jSLNtNDQI3O6S2PWS6D38S+vTBjumKoguj7l6+9plUYlP6lyJvO0+FXs+UzHHFQG
         s8jdBfUngb4do0dOy4pS78HA9qJIyl7blkloJh9pbKgbxEf27LiEC7R3NsmRdczY27HA
         cf6krecDW02CjWUSyuvbDBcfTXkJX9s4lLWYA6BQjWS7bi3HVALV3sGRRMxqJWk8+rqA
         K1Zvby8vf5FIQ2vVF3EUWsgs+e4AKhcX9blqt0gkw+9pydh7N7A/Q8o7EC70rQMUS5CS
         TMlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745299690; x=1745904490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s9TQbRiJMy98ffYqTKpjY3E+dGt1DgpWfOVrNVduG34=;
        b=peMF9ONBytBgTmiwegA77QVOL6uvYjgrvW3jOTh1OezoSuRIaosgfCzgDYbxrLIlc8
         PQWW0NMlG9m9d6ol7yeHQG66MtatxOj9N+3HMCZZOaVAV6JqkQZfZRI5HmT4DHlROmPz
         wc3bQWBFpQHcjlLA6xDIdoOKoBevPxffmpdpCirYCiOKQPAGE5ZedwBlZoSPlSbI1AM1
         ZuA2tqqz0jcPzUrovGPbgU4NXIinXpXeLmp5fry6sw01sxqFiI6cIBccDJmi3pmPWUla
         Z4Aa3hMG78Q/jNjwiDIDYeSLCDxbRyELceKZwC8VoLYpHHwc//EbxXgX8Jt50081MJrO
         juLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUyHbf9VfNZ8Y237OYC/ysdr1w5jfkXDRqJBUvozb0g63coEtHmpTMf+yDkfjS5UsMHs35iA==@lfdr.de
X-Gm-Message-State: AOJu0YyM7GueB5Whn0gYxYdjTRPpBlvVTPL/EeOvoYfMm0Qdu1sXYjT3
	E/a0drhOAtk2Rxpc9ROdJbUPvfF1JhwmBzbOp4JZHbZ+nlJmSned
X-Google-Smtp-Source: AGHT+IFnyi6pJY39EUB4CFcIvcZAjKqiDodYY6vJ5p0qYXmYlXkLReDhVkd05Cj+ZF/eCBYw1DuzYg==
X-Received: by 2002:a92:ca48:0:b0:3d8:8900:9a30 with SMTP id e9e14a558f8ab-3d89428ae3bmr142892105ab.20.1745299689652;
        Mon, 21 Apr 2025 22:28:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKAUufhMFBuAO/hU72HccU8ZWUlBbXcFE8lhpqdXloQfg==
Received: by 2002:a92:90d:0:b0:3d1:9c39:8f7e with SMTP id e9e14a558f8ab-3d81a847054ls28622735ab.2.-pod-prod-07-us;
 Mon, 21 Apr 2025 22:28:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCwS/kPO4+zhC4pE87Kiy1Fm3eT8/WFgrVnaVEMzkSlrV4fO4GDrTjvfp0VWQm3alUa/m7yqj5I74=@googlegroups.com
X-Received: by 2002:a05:6602:358d:b0:861:c759:61fa with SMTP id ca18e2360f4ac-861dbdf49b4mr1686682239f.4.1745299688949;
        Mon, 21 Apr 2025 22:28:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745299688; cv=none;
        d=google.com; s=arc-20240605;
        b=AQMAPAb/HFxqSwvgt5Dv2SHFzsziwUWhrS2s8XvYwse5xHChUwkh/7KXkKvLtFYFLu
         9Scx5fAKSyDHaTgJiY3vRkq7F0rqn/oI/Wu2hj4IND6csjmva8DeYi1M2dCWA231/lNv
         vrPB00WBrnjO5Td1UUSyRQteN+5yCT3r+91L1C7fY4GVPosCZmWFJ26PHBs60pKy6zaw
         1hC88s78E0YAbTgVfKXWFMDteXWNbLGxUcGdWpGGgHzhhrtLg6FSo6jJVTfVp7NCSfOb
         9gYxJlkj/0zFC2r4i4+MQPXjg1bDGINhLYfIegArX82jrXscsBoYv9o2HTDurU/O0ieQ
         5Vzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=78mTUNetXqYVex8eO61oCEX5c5V25/AjtuaH7nzEnMk=;
        fh=TXuCQiOxa4JihKXboOEXFhxQxrNwCHfvOohWStdyQ84=;
        b=GuFVagRMQoJzYHpA/Cm96rG3OD44qAcEVjO4EiOG/y3I2l7oktCc/UNwjwXRJcMEpf
         FRC0MmLIB/SjQ3Ig7eM6Wq7HRhZVJBxq7HeXx+gyzF10C12EdjsQeU+K9S7ahDUCGuLZ
         bIQwniVzqV37xKQPUPKB+PVlpU71b8VZ1VXgAqMb7Ui8QZnVyVOqAWQj8Pr608ww3wtz
         zisEylSsRNWH+1KlL7ZOwq1jTWMUxbViicFmKCgmBKYnD7ddeF3mTSrPtOyTmHpY6HXc
         t8tJLzFfS+O0seNv8DverQ0vakP/jLQehh7GbyN6798SPbDepsIVeH5Q69ZwQF6Kt8UN
         1g8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Ay1d0q7t;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f6a3838694si423364173.4.2025.04.21.22.28.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Apr 2025 22:28:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279862.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53M4Og3t025960;
	Tue, 22 Apr 2025 05:27:53 GMT
Received: from nasanppmta03.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 4644kje2au-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 22 Apr 2025 05:27:52 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA03.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 53M5RqFj021945
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 22 Apr 2025 05:27:52 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 21 Apr 2025 22:27:49 -0700
Date: Tue, 22 Apr 2025 13:27:45 +0800
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Marco Elver <elver@google.com>
CC: Alexander Potapenko <glider@google.com>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, <x86@kernel.org>,
        Aleksandr Nogikh
	<nogikh@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Borislav Petkov
	<bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Dmitry Vyukov
	<dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
        Josh Poimboeuf
	<jpoimboe@kernel.org>,
        Peter Zijlstra <peterz@infradead.org>,
        Thomas Gleixner
	<tglx@linutronix.de>
Subject: Re: [PATCH 3/7] kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
Message-ID: <aAco0cdikKNlbIEN@hu-jiangenj-sha.qualcomm.com>
References: <20250416085446.480069-1-glider@google.com>
 <20250416085446.480069-4-glider@google.com>
 <CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: Yf0ZwQznjw9tWGiM1WmiakrZBMFjnLTt
X-Authority-Analysis: v=2.4 cv=f5pIBPyM c=1 sm=1 tr=0 ts=680728d9 cx=c_pps a=JYp8KDb2vCoCEuGobkYCKw==:117 a=JYp8KDb2vCoCEuGobkYCKw==:17 a=GEpy-HfZoHoA:10 a=kj9zAlcOel0A:10 a=XR8D0OoHHMoA:10 a=1XWaLZrsAAAA:8 a=VwQbUJbxAAAA:8 a=IHZDbfRmWjBfqKslUH8A:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: Yf0ZwQznjw9tWGiM1WmiakrZBMFjnLTt
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-22_02,2025-04-21_02,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 malwarescore=0
 mlxlogscore=837 mlxscore=0 impostorscore=0 adultscore=0 priorityscore=1501
 clxscore=1011 suspectscore=0 bulkscore=0 spamscore=0 lowpriorityscore=0
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2502280000
 definitions=main-2504220040
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Ay1d0q7t;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131
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

On Thu, Apr 17, 2025 at 09:43:20PM +0200, Marco Elver wrote:
> On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wrote:
> >
> > The new config switches coverage instrumentation to using
> >   __sanitizer_cov_trace_pc_guard(u32 *guard)
> > instead of
> >   __sanitizer_cov_trace_pc(void)
> >
> > Each callback receives a unique 32-bit guard variable residing in the
> > __sancov_guards section. Those guards can be used by kcov to deduplicate
> > the coverage on the fly.
> >
> > As a first step, we make the new instrumentation mode 1:1 compatible with
> > the old one.
> >
> > Cc: x86@kernel.org
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  arch/x86/kernel/vmlinux.lds.S     |  1 +
> >  include/asm-generic/vmlinux.lds.h | 14 ++++++-
> >  include/linux/kcov.h              |  2 +
> >  kernel/kcov.c                     | 61 +++++++++++++++++++++----------
> >  lib/Kconfig.debug                 | 16 ++++++++
> >  scripts/Makefile.kcov             |  4 ++
> >  scripts/module.lds.S              | 23 ++++++++++++
> >  tools/objtool/check.c             |  1 +
> >  8 files changed, 101 insertions(+), 21 deletions(-)
> >
> > diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
> > index 0deb4887d6e96..2acfbbde33820 100644
> > --- a/arch/x86/kernel/vmlinux.lds.S
> > +++ b/arch/x86/kernel/vmlinux.lds.S
> > @@ -390,6 +390,7 @@ SECTIONS
> >                 . = ALIGN(PAGE_SIZE);
> >                 __bss_stop = .;
> >         }
> > +       SANCOV_GUARDS_BSS
> 
> Right now this will be broken on other architectures, right?
I did a test on arm64, after adding SANCOV_GUARDS_BSS, it reports
missing support for R_AARCH64_ADR_GOT_PAGE and
R_AARCH64_LD64_GOT_LO12_NC.
> 
> >         /*
> >          * The memory occupied from _text to here, __end_of_kernel_reserve, is
> > diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> > index 0d5b186abee86..3ff150f152737 100644
> > --- a/include/asm-generic/vmlinux.lds.h
> > +++ b/include/asm-generic/vmlinux.lds.h
> > @@ -102,7 +102,8 @@
> >   * sections to be brought in with rodata.
> >   */
> >  #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LTO_CLANG) || \
> > -defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> > +       defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG) || \
> > +       defined(CONFIG_KCOV_ENABLE_GUARDS)
> >  #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
> >  #else
> >  #define TEXT_MAIN .text
> > @@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> >  #define SBSS_MAIN .sbss
> >  #endif
> >
> > +#if defined(CONFIG_KCOV_ENABLE_GUARDS)
> > +#define SANCOV_GUARDS_BSS                      \
> > +       __sancov_guards(NOLOAD) : {             \
> > +               __start___sancov_guards = .;    \
> > +               *(__sancov_guards);             \
> > +               __stop___sancov_guards = .;     \
> > +       }
> > +#else
> > +#define SANCOV_GUARDS_BSS
> > +#endif
> > +
> >  /*
> >   * GCC 4.5 and later have a 32 bytes section alignment for structures.
> >   * Except GCC 4.9, that feels the need to align on 64 bytes.
> > diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> > index e1f7d793c1cb3..7ec2669362fd1 100644
> > --- a/include/linux/kcov.h
> > +++ b/include/linux/kcov.h
> > @@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
> >  #endif
> >
> >  void __sanitizer_cov_trace_pc(void);
> > +void __sanitizer_cov_trace_pc_guard(u32 *guard);
> > +void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
> >  void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
> >  void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
> >  void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index 8fcbca236bec5..b97f429d17436 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -193,27 +193,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
> >         return ip;
> >  }
> >
> > -/*
> > - * Entry point from instrumented code.
> > - * This is called once per basic-block/edge.
> > - */
> > -void notrace __sanitizer_cov_trace_pc(void)
> > +static void sanitizer_cov_write_subsequent(unsigned long *area, int size,
> 
> notrace is missing.
> 
> Can we give this a more descriptive name? E.g. "kcov_append" ?
> 
> > +                                          unsigned long ip)
> >  {
> > -       struct task_struct *t;
> > -       unsigned long *area;
> > -       unsigned long ip = canonicalize_ip(_RET_IP_);
> > -       unsigned long pos;
> > -
> > -       t = current;
> > -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > -               return;
> > -
> > -       area = t->kcov_state.s.area;
> >         /* The first 64-bit word is the number of subsequent PCs. */
> > -       pos = READ_ONCE(area[0]) + 1;
> > -       if (likely(pos < t->kcov_state.s.size)) {
> > -               /* Previously we write pc before updating pos. However, some
> > -                * early interrupt code could bypass check_kcov_mode() check
> > +       unsigned long pos = READ_ONCE(area[0]) + 1;
> > +
> > +       if (likely(pos < size)) {
> > +               /*
> > +                * Some early interrupt code could bypass check_kcov_mode() check
> >                  * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
> >                  * raised between writing pc and updating pos, the pc could be
> >                  * overitten by the recursive __sanitizer_cov_trace_pc().
> > @@ -224,7 +212,40 @@ void notrace __sanitizer_cov_trace_pc(void)
> >                 area[pos] = ip;
> >         }
> >  }
> > +
> > +/*
> > + * Entry point from instrumented code.
> > + * This is called once per basic-block/edge.
> > + */
> > +#ifndef CONFIG_KCOV_ENABLE_GUARDS
> 
> Negation makes it harder to read - just #ifdef, and swap the branches below.
> 
> > +void notrace __sanitizer_cov_trace_pc(void)
> > +{
> > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > +               return;
> > +
> > +       sanitizer_cov_write_subsequent(current->kcov_state.s.area,
> > +                                      current->kcov_state.s.size,
> > +                                      canonicalize_ip(_RET_IP_));
> > +}
> >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> > +#else
> > +void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> > +{
> > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > +               return;
> > +
> > +       sanitizer_cov_write_subsequent(current->kcov_state.s.area,
> > +                                      current->kcov_state.s.size,
> > +                                      canonicalize_ip(_RET_IP_));
> > +}
> > +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> > +
> > +void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
> > +                                                uint32_t *stop)
> > +{
> > +}
> > +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
> > +#endif
> >
> >  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
> >  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> > @@ -252,7 +273,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >         start_index = 1 + count * KCOV_WORDS_PER_CMP;
> >         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
> >         if (likely(end_pos <= max_pos)) {
> > -               /* See comment in __sanitizer_cov_trace_pc(). */
> > +               /* See comment in sanitizer_cov_write_subsequent(). */
> >                 WRITE_ONCE(area[0], count + 1);
> >                 barrier();
> >                 area[start_index] = type;
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 35796c290ca35..a81d086b8e1ff 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -2135,6 +2135,8 @@ config ARCH_HAS_KCOV
> >  config CC_HAS_SANCOV_TRACE_PC
> >         def_bool $(cc-option,-fsanitize-coverage=trace-pc)
> >
> > +config CC_HAS_SANCOV_TRACE_PC_GUARD
> > +       def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
> >
> >  config KCOV
> >         bool "Code coverage for fuzzing"
> > @@ -2151,6 +2153,20 @@ config KCOV
> >
> >           For more details, see Documentation/dev-tools/kcov.rst.
> >
> > +config KCOV_ENABLE_GUARDS
> 
> The "ENABLE" here seems redundant.
> Just KCOV_GUARDS should be clear enough.
> 
> > +       depends on KCOV
> > +       depends on CC_HAS_SANCOV_TRACE_PC_GUARD
> > +       bool "Use fsanitize-coverage=trace-pc-guard for kcov"
> 
> The compiler option is an implementation detail - it might be more
> helpful to have this say "Use coverage guards for kcov".
> 
> > +       help
> > +         Use coverage guards instrumentation for kcov, passing
> > +         -fsanitize-coverage=trace-pc-guard to the compiler.
> > +
> > +         Every coverage callback is associated with a global variable that
> > +         allows to efficiently deduplicate coverage at collection time.
> > +
> > +         This comes at a cost of increased binary size (4 bytes of .bss
> > +         per basic block, plus 1-2 instructions to pass an extra parameter).
> > +
> >  config KCOV_ENABLE_COMPARISONS
> >         bool "Enable comparison operands collection by KCOV"
> >         depends on KCOV
> > diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> > index 67e8cfe3474b7..ec63d471d5773 100644
> > --- a/scripts/Makefile.kcov
> > +++ b/scripts/Makefile.kcov
> > @@ -1,5 +1,9 @@
> >  # SPDX-License-Identifier: GPL-2.0-only
> > +ifeq ($(CONFIG_KCOV_ENABLE_GUARDS),y)
> > +kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD) += -fsanitize-coverage=trace-pc-guard
> 
> This can just be kcov-flags-y, because CONFIG_KCOV_ENABLE_GUARDS
> implies CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD.
> 
> > +else
> >  kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    += -fsanitize-coverage=trace-pc
> > +endif
> >  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   += -fsanitize-coverage=trace-cmp
> >  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
> >
> > diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> > index 450f1088d5fd3..ec7e9247f8de6 100644
> > --- a/scripts/module.lds.S
> > +++ b/scripts/module.lds.S
> > @@ -64,6 +64,29 @@ SECTIONS {
> >                 MOD_CODETAG_SECTIONS()
> >         }
> >  #endif
> > +
> > +#ifdef CONFIG_KCOV_ENABLE_GUARDS
> > +       __sancov_guards(NOLOAD) : {
> > +               __start___sancov_guards = .;
> > +               *(__sancov_guards);
> > +               __stop___sancov_guards = .;
> > +       }
> > +
> > +       .text : {
> > +               *(.text .text.[0-9a-zA-Z_]*)
> > +               *(.text..L*)
> > +       }
> > +
> > +       .init.text : {
> > +               *(.init.text .init.text.[0-9a-zA-Z_]*)
> > +               *(.init.text..L*)
> > +       }
> > +       .exit.text : {
> > +               *(.exit.text .exit.text.[0-9a-zA-Z_]*)
> > +               *(.exit.text..L*)
> > +       }
> > +#endif
> > +
> >         MOD_SEPARATE_CODETAG_SECTIONS()
> >  }
> >
> > diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> > index ce973d9d8e6d8..a5db690dd2def 100644
> > --- a/tools/objtool/check.c
> > +++ b/tools/objtool/check.c
> > @@ -1149,6 +1149,7 @@ static const char *uaccess_safe_builtin[] = {
> >         "write_comp_data",
> >         "check_kcov_mode",
> >         "__sanitizer_cov_trace_pc",
> > +       "__sanitizer_cov_trace_pc_guard",
> >         "__sanitizer_cov_trace_const_cmp1",
> >         "__sanitizer_cov_trace_const_cmp2",
> >         "__sanitizer_cov_trace_const_cmp4",
> > --
> > 2.49.0.604.gff1f9ca942-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aAco0cdikKNlbIEN%40hu-jiangenj-sha.qualcomm.com.
