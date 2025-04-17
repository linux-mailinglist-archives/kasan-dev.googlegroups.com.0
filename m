Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL7BQTAAMGQEKZVUZXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32D3AA922F4
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 18:47:45 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-47ae87b5182sf4991221cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 09:47:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744908464; cv=pass;
        d=google.com; s=arc-20240605;
        b=dDPq4GX3e7yg32W2w8vM5p+QN+64U4VPwgcQOXsMgjvj2YXo0pCEnvsziDnhwDE5CY
         qRglCl0ln2BlknmDyTp7trt8V5w8wNOOy3fKttmU7i6nVkzqQkpWb3VKRuC2yRNQgKEt
         U3oBWmf0+bhNWgl8W641fMewOop3iILwWL5g8FjlyhMdOoEX/UmThuR+lvi1b57CJ2Ea
         oSoPvv+3f1X3q43qr+uGvTT0gMHpv/53FPLy3X9Ev547vM+nti1cr6LmKIIX3I3d22/S
         BA37r+f/pwqOWVuwlYRWhTNCjZoo2oxIM6Go//bJbPnXPdWE9HMpUMTbcN+EXsqEH409
         OaLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4MHoJwJrGFGLF9tcGkeoTAGfJtEm8go9omqHybR3AIg=;
        fh=f1u2CUEGjiHfwfXXQDsdlK85hcj8Az5X7fmheRdt9+M=;
        b=k5VKiQ4cYC3HdXAB6cIWt8vtyAEzOryAZMBg3hsxPyR6HH4Sr2lcYlCbV4Z4RpBRgd
         E6PSlwBux/I8BYEW23VsClbPmEGwMreL47QFO9/1Nqvdsq8zzkmvpl7WIjEGiG4DMQb/
         gTgn8Ndkf9lOs4bWwyCVC7aQA7i2IngL11Shx0gB//VRkQ/AEu0zd8hYSD+6xq6HK4t6
         gH5Zzk+N/wB0hFH47on9s9wjjix1QpWuiDJrLBMz2yUjGaEbVEaxeVuFRrJkds7e/xQx
         eJKD+BSOHoX0VEsnqtTSFtF3MBZ5A14rMQOZ+Rmalbp2xWQPDA8mL9iDmS2Kj8lTW0iz
         LCGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LeAn45fV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744908464; x=1745513264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4MHoJwJrGFGLF9tcGkeoTAGfJtEm8go9omqHybR3AIg=;
        b=jg34ZddqjPuDXNEPlicpUbYgEQ1hf1Q39oKkcs7+WM31KXnDqZ1mFt/e0rkI6VQ4/Q
         NfTuNxu7qXZEBOnZYABc/xbT8ixPFvZCFOsbjyL/6XBS1K6wpgZkTcSMDi7NPtu2rtgf
         k1EwhjR079LTTJxPecUwMykGYT7Zjcn60PW6UkMjRMcJz3Ar3gah2LPYW/GOSEUtwaoB
         rM7DwLEwKL/Ihw8OsScfLYxq+/6bGXd/B7JMi1uw9A2/lOkRIK/lRCeri48zOg/I8O8a
         +MgBrDGK8SzoxI35KhD6rCAMaqF1HVUBcAUKlIxhym9Fq/pNEG9TpfI4mLGbOdGOajhS
         eezw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744908464; x=1745513264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4MHoJwJrGFGLF9tcGkeoTAGfJtEm8go9omqHybR3AIg=;
        b=o6hL334s351fdC2KN++xK69Ym3k4SHjFIP776Pwp1JjGUugzZQvuyvYzbc8CUb4kpN
         eUspfREDq8g6fHX8KjH4l68tfiXhoSnN+5sIPhcFZ0ftpheglOus2y0kkYJkOdReLKVS
         /FqskDO2M7ALXHkRdGVsS3cdIwSNYE9NHof3/yHwpJUJvR8uO5S/6/lj1Yzn7G8gCPWZ
         NTJqa0uQ9z/Q7XSPrQpnjgFE4X59Wh2CkCHOM4Hx18ZKWOygOb8YzEWe0vDaXPrJMS65
         92RJbYOZt6iMMAurTTE3vPTeARHQjMZO+AlOpZ7UxgjDP39EBwLZnaIWzk8xH6pCrxgX
         xkbg==
X-Forwarded-Encrypted: i=2; AJvYcCVIRKKykoLhVpxz7zZlagFZld2cvJwV5AnNVdFak3u+ceccEbGMIS3AzE1zF4G6TyJfMXwzSQ==@lfdr.de
X-Gm-Message-State: AOJu0YyC9ryYAutkp/pvqNguf/+Jg/RNVOKiyAe2ka+Uz9bi3LKvrh20
	X3Q1bUx56ae0Oc0dBq2WZOzF+wp5O35ZGlRSxhuJwCkIAQZ9hDYw
X-Google-Smtp-Source: AGHT+IEVcc04XzPygpL4BI67uFvhD34zyXKucq/5ECaBOYacdW/4J2bbxp9PUP3wJHud1f9b2cHGKQ==
X-Received: by 2002:a05:6214:1311:b0:6e8:f2aa:a8b0 with SMTP id 6a1803df08f44-6f2b2f8b9c5mr104490226d6.18.1744908464075;
        Thu, 17 Apr 2025 09:47:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALBdsYh0R8nEnMxehFWZ2Fziqf2s/88o890LiLW0mYGvw==
Received: by 2002:a0c:f607:0:b0:6e8:f3c7:337d with SMTP id 6a1803df08f44-6f2b995f66als9677496d6.0.-pod-prod-09-us;
 Thu, 17 Apr 2025 09:47:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTiWdCcHFDhIH+IpMKUjY+Xxpn20tNRVTGdZzIvGn+pPEYUL6RPoM0V7mcKzrGKiLBPcwRrtid2Gc=@googlegroups.com
X-Received: by 2002:a05:6214:c21:b0:6e8:86d3:be73 with SMTP id 6a1803df08f44-6f2b307d4c5mr106622126d6.37.1744908462693;
        Thu, 17 Apr 2025 09:47:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744908462; cv=none;
        d=google.com; s=arc-20240605;
        b=ddSEDLojmEuQOXJE9wyaiRLB1gPTeNbG50155C/LHlMZQxy/MzWmIFza8iOCPJtEnu
         m/AhycT6WL3N3D6Wjf1LWWURvRZ5MmUinM3qsAOAGc3jtp+onDfkd6aJiYWSnBO2ccnT
         BpAyDGUR4ii9FpiZB3sLVt8q4wSqa4eWhwsvsfIY5iO9Tr1+WHzJCDf2uBO1wDR6WEng
         /dXiSapoy8FKC3x6/0xcMN3+GONgmMjdBSM0d5w+qLbGlTYhgAkchI72itXgbBkZ4yGK
         Yo/qVmFJ9YIBOye2hvGPKBv2iJM82YKpJKOacygGBIRazBT3v+ojRCTPWnehPnHTk5CW
         LBoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gZRP9XBy/IaMFQgXk543Y2umGGrzdPzuqMhR+6DtFWo=;
        fh=WdgvrEGaQ4kv9moVPL6KFj/PJBkNTj5dmHt1PIyPodA=;
        b=fvmev6Nw1Hzymj3jSHv07qgi2hQP5R+hsN8wKYSsX5Mlryv9k9bJGwU9jEfa90pO6l
         tNx2rkd9VqJ4yMGYx9FE8ab3YCodCsJ5BgrnmtXwVsoQzs9/ojjWYadGUb62VeI48c7g
         kewUDAAAGHJMLz9iwR4YmiupJtqEVVaL1pdPgCUdmer1cElyWauCb+S/C1pfxs1iaGeu
         rEsF2G0Xw+LyGqDGTqQYv+pqZcxM6r5yRS/DmHhB95yK6V0lBRfHI7y2gg+XCLs9GSyP
         vYNP0VIlGwRyeKgh3rWJ3nyX6bOIYF56KGzf89xCykLCmfRbssw4Fw4r/FKnhR34PhI4
         GaRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LeAn45fV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f2c2be9bc0si99226d6.5.2025.04.17.09.47.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 09:47:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-301918a4e1bso814221a91.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 09:47:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUM3dEMdF2OzX9UhyQ3SWjjFayFk0MgHfecQvo1K4LNQTdjVxvO9RV26mkOOnOTMv0cNeT8YFItNv4=@googlegroups.com
X-Gm-Gg: ASbGncvMp+EbGmOFdQctwAWqjhbizzL6pl/ayoVImrpPptEhtLpFFsRoX0cHDO4DP3n
	ozedK86Va+Atdk9MFp+mPddx5wv9n68Fm6NAnWw6ugR+iEfolFUWIcZImUrTx4Gs4iwOk9QZoKZ
	83SSr4sVu3JnayZoxdi8Ljd8Ycl+KfXJ5As9fUNNNkL4KkD85f5C/P4w==
X-Received: by 2002:a17:90b:544f:b0:2f9:c144:9d13 with SMTP id
 98e67ed59e1d1-3086415ce82mr10501876a91.24.1744908461443; Thu, 17 Apr 2025
 09:47:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-2-glider@google.com>
In-Reply-To: <20250416085446.480069-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 18:47:04 +0200
X-Gm-Features: ATxdqUGZDGtRxNj3H8LE4NWhNfntkrsSoxVZ57KseDO79LBBDvcbLH0XlWj5KFM
Message-ID: <CANpmjNPass_tPdjwguw5N+5HRn81FOJm0axLDMxwbZLrHHH8hg@mail.gmail.com>
Subject: Re: [PATCH 1/7] kcov: apply clang-format to kcov code
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LeAn45fV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wrote:
>
> kcov used to obey clang-format style, but somehow diverged over time.
> This patch applies clang-format to kernel/kcov.c and
> include/linux/kcov.h, no functional change.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  include/linux/kcov.h |  54 +++++++++++------
>  kernel/kcov.c        | 134 ++++++++++++++++++++++---------------------
>  2 files changed, 105 insertions(+), 83 deletions(-)
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 75a2fb8b16c32..932b4face1005 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -25,20 +25,20 @@ enum kcov_mode {
>         KCOV_MODE_REMOTE = 4,
>  };
>
> -#define KCOV_IN_CTXSW  (1 << 30)
> +#define KCOV_IN_CTXSW (1 << 30)
>
>  void kcov_task_init(struct task_struct *t);
>  void kcov_task_exit(struct task_struct *t);
>
> -#define kcov_prepare_switch(t)                 \
> -do {                                           \
> -       (t)->kcov_mode |= KCOV_IN_CTXSW;        \
> -} while (0)
> +#define kcov_prepare_switch(t)                   \
> +       do {                                     \
> +               (t)->kcov_mode |= KCOV_IN_CTXSW; \
> +       } while (0)
>
> -#define kcov_finish_switch(t)                  \
> -do {                                           \
> -       (t)->kcov_mode &= ~KCOV_IN_CTXSW;       \
> -} while (0)
> +#define kcov_finish_switch(t)                     \
> +       do {                                      \
> +               (t)->kcov_mode &= ~KCOV_IN_CTXSW; \
> +       } while (0)
>
>  /* See Documentation/dev-tools/kcov.rst for usage details. */
>  void kcov_remote_start(u64 handle);
> @@ -119,23 +119,41 @@ void __sanitizer_cov_trace_switch(kcov_u64 val, void *cases);
>
>  #else
>
> -static inline void kcov_task_init(struct task_struct *t) {}
> -static inline void kcov_task_exit(struct task_struct *t) {}
> -static inline void kcov_prepare_switch(struct task_struct *t) {}
> -static inline void kcov_finish_switch(struct task_struct *t) {}
> -static inline void kcov_remote_start(u64 handle) {}
> -static inline void kcov_remote_stop(void) {}
> +static inline void kcov_task_init(struct task_struct *t)
> +{
> +}
> +static inline void kcov_task_exit(struct task_struct *t)
> +{
> +}
> +static inline void kcov_prepare_switch(struct task_struct *t)
> +{
> +}
> +static inline void kcov_finish_switch(struct task_struct *t)
> +{
> +}
> +static inline void kcov_remote_start(u64 handle)
> +{
> +}
> +static inline void kcov_remote_stop(void)
> +{
> +}

This excessive-new-line style is not an improvement over previously.
But nothing we can do about I guess...

>  static inline u64 kcov_common_handle(void)
>  {
>         return 0;
>  }
> -static inline void kcov_remote_start_common(u64 id) {}
> -static inline void kcov_remote_start_usb(u64 id) {}
> +static inline void kcov_remote_start_common(u64 id)
> +{
> +}
> +static inline void kcov_remote_start_usb(u64 id)
> +{
> +}
>  static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
>  {
>         return 0;
>  }
> -static inline void kcov_remote_stop_softirq(unsigned long flags) {}
> +static inline void kcov_remote_stop_softirq(unsigned long flags)
> +{
> +}
>
>  #endif /* CONFIG_KCOV */
>  #endif /* _LINUX_KCOV_H */
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 187ba1b80bda1..7cc6123c2baa4 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -4,27 +4,28 @@
>  #define DISABLE_BRANCH_PROFILING
>  #include <linux/atomic.h>
>  #include <linux/compiler.h>
> +#include <linux/debugfs.h>
>  #include <linux/errno.h>
>  #include <linux/export.h>
> -#include <linux/types.h>
>  #include <linux/file.h>
>  #include <linux/fs.h>
>  #include <linux/hashtable.h>
>  #include <linux/init.h>
>  #include <linux/jiffies.h>
> +#include <linux/kcov.h>
>  #include <linux/kmsan-checks.h>
> +#include <linux/log2.h>
>  #include <linux/mm.h>
>  #include <linux/preempt.h>
>  #include <linux/printk.h>
> +#include <linux/refcount.h>
>  #include <linux/sched.h>
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
> -#include <linux/vmalloc.h>
> -#include <linux/debugfs.h>
> +#include <linux/types.h>
>  #include <linux/uaccess.h>
> -#include <linux/kcov.h>
> -#include <linux/refcount.h>
> -#include <linux/log2.h>
> +#include <linux/vmalloc.h>
> +
>  #include <asm/setup.h>
>
>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
> @@ -52,36 +53,36 @@ struct kcov {
>          *  - task with enabled coverage (we can't unwire it from another task)
>          *  - each code section for remote coverage collection
>          */
> -       refcount_t              refcount;
> +       refcount_t refcount;
>         /* The lock protects mode, size, area and t. */
> -       spinlock_t              lock;
> -       enum kcov_mode          mode;
> +       spinlock_t lock;
> +       enum kcov_mode mode;
>         /* Size of arena (in long's). */
> -       unsigned int            size;
> +       unsigned int size;
>         /* Coverage buffer shared with user space. */
> -       void                    *area;
> +       void *area;
>         /* Task for which we collect coverage, or NULL. */
> -       struct task_struct      *t;
> +       struct task_struct *t;
>         /* Collecting coverage from remote (background) threads. */
> -       bool                    remote;
> +       bool remote;
>         /* Size of remote area (in long's). */
> -       unsigned int            remote_size;
> +       unsigned int remote_size;
>         /*
>          * Sequence is incremented each time kcov is reenabled, used by
>          * kcov_remote_stop(), see the comment there.
>          */
> -       int                     sequence;
> +       int sequence;
>  };
>
>  struct kcov_remote_area {
> -       struct list_head        list;
> -       unsigned int            size;
> +       struct list_head list;
> +       unsigned int size;
>  };
>
>  struct kcov_remote {
> -       u64                     handle;
> -       struct kcov             *kcov;
> -       struct hlist_node       hnode;
> +       u64 handle;
> +       struct kcov *kcov;
> +       struct hlist_node hnode;
>  };
>
>  static DEFINE_SPINLOCK(kcov_remote_lock);
> @@ -89,14 +90,14 @@ static DEFINE_HASHTABLE(kcov_remote_map, 4);
>  static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>
>  struct kcov_percpu_data {
> -       void                    *irq_area;
> -       local_lock_t            lock;
> -
> -       unsigned int            saved_mode;
> -       unsigned int            saved_size;
> -       void                    *saved_area;
> -       struct kcov             *saved_kcov;
> -       int                     saved_sequence;
> +       void *irq_area;
> +       local_lock_t lock;
> +
> +       unsigned int saved_mode;
> +       unsigned int saved_size;
> +       void *saved_area;
> +       struct kcov *saved_kcov;
> +       int saved_sequence;
>  };
>
>  static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
> @@ -149,7 +150,7 @@ static struct kcov_remote_area *kcov_remote_area_get(unsigned int size)
>
>  /* Must be called with kcov_remote_lock locked. */
>  static void kcov_remote_area_put(struct kcov_remote_area *area,
> -                                       unsigned int size)
> +                                unsigned int size)
>  {
>         INIT_LIST_HEAD(&area->list);
>         area->size = size;
> @@ -171,7 +172,8 @@ static __always_inline bool in_softirq_really(void)
>         return in_serving_softirq() && !in_hardirq() && !in_nmi();
>  }
>
> -static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
> +static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
> +                                   struct task_struct *t)
>  {
>         unsigned int mode;
>
> @@ -354,8 +356,8 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
>  #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
>
>  static void kcov_start(struct task_struct *t, struct kcov *kcov,
> -                       unsigned int size, void *area, enum kcov_mode mode,
> -                       int sequence)
> +                      unsigned int size, void *area, enum kcov_mode mode,
> +                      int sequence)
>  {
>         kcov_debug("t = %px, size = %u, area = %px\n", t, size, area);
>         t->kcov = kcov;
> @@ -566,14 +568,14 @@ static void kcov_fault_in_area(struct kcov *kcov)
>  }
>
>  static inline bool kcov_check_handle(u64 handle, bool common_valid,
> -                               bool uncommon_valid, bool zero_valid)
> +                                    bool uncommon_valid, bool zero_valid)
>  {
>         if (handle & ~(KCOV_SUBSYSTEM_MASK | KCOV_INSTANCE_MASK))
>                 return false;
>         switch (handle & KCOV_SUBSYSTEM_MASK) {
>         case KCOV_SUBSYSTEM_COMMON:
> -               return (handle & KCOV_INSTANCE_MASK) ?
> -                       common_valid : zero_valid;
> +               return (handle & KCOV_INSTANCE_MASK) ? common_valid :
> +                                                      zero_valid;
>         case KCOV_SUBSYSTEM_USB:
>                 return uncommon_valid;
>         default:
> @@ -611,7 +613,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 kcov_fault_in_area(kcov);
>                 kcov->mode = mode;
>                 kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
> -                               kcov->sequence);
> +                          kcov->sequence);
>                 kcov->t = t;
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
> @@ -642,40 +644,40 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                         return -EINVAL;
>                 kcov->mode = mode;
>                 t->kcov = kcov;
> -               t->kcov_mode = KCOV_MODE_REMOTE;
> +               t->kcov_mode = KCOV_MODE_REMOTE;
>                 kcov->t = t;
>                 kcov->remote = true;
>                 kcov->remote_size = remote_arg->area_size;
>                 spin_lock_irqsave(&kcov_remote_lock, flags);
>                 for (i = 0; i < remote_arg->num_handles; i++) {
> -                       if (!kcov_check_handle(remote_arg->handles[i],
> -                                               false, true, false)) {
> +                       if (!kcov_check_handle(remote_arg->handles[i], false,
> +                                              true, false)) {
>                                 spin_unlock_irqrestore(&kcov_remote_lock,
> -                                                       flags);
> +                                                      flags);
>                                 kcov_disable(t, kcov);
>                                 return -EINVAL;
>                         }
>                         remote = kcov_remote_add(kcov, remote_arg->handles[i]);
>                         if (IS_ERR(remote)) {
>                                 spin_unlock_irqrestore(&kcov_remote_lock,
> -                                                       flags);
> +                                                      flags);
>                                 kcov_disable(t, kcov);
>                                 return PTR_ERR(remote);
>                         }
>                 }
>                 if (remote_arg->common_handle) {
> -                       if (!kcov_check_handle(remote_arg->common_handle,
> -                                               true, false, false)) {
> +                       if (!kcov_check_handle(remote_arg->common_handle, true,
> +                                              false, false)) {
>                                 spin_unlock_irqrestore(&kcov_remote_lock,
> -                                                       flags);
> +                                                      flags);
>                                 kcov_disable(t, kcov);
>                                 return -EINVAL;
>                         }
>                         remote = kcov_remote_add(kcov,
> -                                       remote_arg->common_handle);
> +                                                remote_arg->common_handle);
>                         if (IS_ERR(remote)) {
>                                 spin_unlock_irqrestore(&kcov_remote_lock,
> -                                                       flags);
> +                                                      flags);
>                                 kcov_disable(t, kcov);
>                                 return PTR_ERR(remote);
>                         }
> @@ -728,13 +730,15 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                 spin_unlock_irqrestore(&kcov->lock, flags);
>                 return 0;
>         case KCOV_REMOTE_ENABLE:
> -               if (get_user(remote_num_handles, (unsigned __user *)(arg +
> -                               offsetof(struct kcov_remote_arg, num_handles))))
> +               if (get_user(remote_num_handles,
> +                            (unsigned __user *)(arg +
> +                                                offsetof(struct kcov_remote_arg,
> +                                                         num_handles))))

Ouch. Maybe move the address calculation before and assign to
temporary to avoid this mess?

>                         return -EFAULT;
>                 if (remote_num_handles > KCOV_REMOTE_MAX_HANDLES)
>                         return -EINVAL;
> -               remote_arg_size = struct_size(remote_arg, handles,
> -                                       remote_num_handles);
> +               remote_arg_size =
> +                       struct_size(remote_arg, handles, remote_num_handles);
>                 remote_arg = memdup_user((void __user *)arg, remote_arg_size);
>                 if (IS_ERR(remote_arg))
>                         return PTR_ERR(remote_arg);
> @@ -758,11 +762,11 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  }
>
>  static const struct file_operations kcov_fops = {
> -       .open           = kcov_open,
> -       .unlocked_ioctl = kcov_ioctl,
> -       .compat_ioctl   = kcov_ioctl,
> -       .mmap           = kcov_mmap,
> -       .release        = kcov_close,
> +       .open = kcov_open,
> +       .unlocked_ioctl = kcov_ioctl,
> +       .compat_ioctl = kcov_ioctl,
> +       .mmap = kcov_mmap,
> +       .release = kcov_close,
>  };
>
>  /*
> @@ -836,8 +840,8 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
>
>         if (data->saved_kcov) {
>                 kcov_start(t, data->saved_kcov, data->saved_size,
> -                               data->saved_area, data->saved_mode,
> -                               data->saved_sequence);
> +                          data->saved_area, data->saved_mode,
> +                          data->saved_sequence);
>                 data->saved_mode = 0;
>                 data->saved_size = 0;
>                 data->saved_area = NULL;
> @@ -891,7 +895,7 @@ void kcov_remote_start(u64 handle)
>                 return;
>         }
>         kcov_debug("handle = %llx, context: %s\n", handle,
> -                       in_task() ? "task" : "softirq");
> +                  in_task() ? "task" : "softirq");
>         kcov = remote->kcov;
>         /* Put in kcov_remote_stop(). */
>         kcov_get(kcov);
> @@ -931,12 +935,11 @@ void kcov_remote_start(u64 handle)
>         kcov_start(t, kcov, size, area, mode, sequence);
>
>         local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> -
>  }
>  EXPORT_SYMBOL(kcov_remote_start);
>
>  static void kcov_move_area(enum kcov_mode mode, void *dst_area,
> -                               unsigned int dst_area_size, void *src_area)
> +                          unsigned int dst_area_size, void *src_area)
>  {
>         u64 word_size = sizeof(unsigned long);
>         u64 count_size, entry_size_log;
> @@ -944,8 +947,8 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
>         void *dst_entries, *src_entries;
>         u64 dst_occupied, dst_free, bytes_to_move, entries_moved;
>
> -       kcov_debug("%px %u <= %px %lu\n",
> -               dst_area, dst_area_size, src_area, *(unsigned long *)src_area);
> +       kcov_debug("%px %u <= %px %lu\n", dst_area, dst_area_size, src_area,
> +                  *(unsigned long *)src_area);
>
>         switch (mode) {
>         case KCOV_MODE_TRACE_PC:
> @@ -967,8 +970,8 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
>         }
>
>         /* As arm can't divide u64 integers use log of entry size. */
> -       if (dst_len > ((dst_area_size * word_size - count_size) >>
> -                               entry_size_log))
> +       if (dst_len >
> +           ((dst_area_size * word_size - count_size) >> entry_size_log))
>                 return;
>         dst_occupied = count_size + (dst_len << entry_size_log);
>         dst_free = dst_area_size * word_size - dst_occupied;
> @@ -1100,7 +1103,8 @@ static int __init kcov_init(void)
>
>         for_each_possible_cpu(cpu) {
>                 void *area = vmalloc_node(CONFIG_KCOV_IRQ_AREA_SIZE *
> -                               sizeof(unsigned long), cpu_to_node(cpu));
> +                                                 sizeof(unsigned long),
> +                                         cpu_to_node(cpu));

Ouch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPass_tPdjwguw5N%2B5HRn81FOJm0axLDMxwbZLrHHH8hg%40mail.gmail.com.
