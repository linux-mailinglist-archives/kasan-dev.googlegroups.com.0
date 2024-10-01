Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPX7563QMGQEPOJMZYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D320398BEA0
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2024 15:57:19 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6c513582b05sf96875266d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 06:57:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727791038; cv=pass;
        d=google.com; s=arc-20240605;
        b=KViJvFYmdYehmcA15xpSUvNzyfr2ciMCGxwxjkdIsrGIWuRulbohNvbpaTstTUk6Tt
         4RNKZJvZ4kRL0QHgqMvJewaFjnGncJGkqGVG87XzQeQokqIW1ckxfGulEqV9ARg7LgK1
         VFPgwIJ4C4cVo6Cy1hv0Jmdml0/gyp8FqCoFdD/o2VeuLBo0QuPVHyqaPtEuWfzmjPoR
         4cPVZpbqubGFRf3CS+j3b491+x5I5/BKTKqxeB4lX08h4XeU2rG0J8oIFggGCR7DnY3j
         13z8PYzka39MGaLZJwVdPE1FoEXzjXiqhlJaIfaQX1i4fyg65PBV/VZciri4YzxJJGke
         KeLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B4jCmXmpS2iZoImmfRieVfG5HdqwH8Az+syaaeoOy6U=;
        fh=njakpFpMz1AV1Th2ogpcHedVC7mEKBNata6nOiAA75o=;
        b=Lu2CgqY1bdlQigkl4AqUF07a7O66F3vwP4g0A4mZUKmhoYNXUG1RhRU2hP+H12/Jfk
         +PmZ1PkaoUSy1QZzexGdHFYDEPZeTA/DIF/cH9WHjFtaMfvTHAU+mJ7AOFV8RgcCJVnw
         nTiSld0MYDpx5sdT1hB20eBODbshKaT3AFPC9/wqmYMuKvCjs5Awx+1uOU2ysxIiVCx/
         tc3NkiISZEFI9x/s0DTInwjv1xn4p5oPPRqGg6CR8fKuLN63HL+QQN4EQdEZsmPHB4+c
         4WgN/U2KBYBpF/zBW//O4FpYmYaru5oP+SI7TB7ILUww58lVJqTaC8DFqFUEM/Zzy5fy
         Y+BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vpD/nUMy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727791038; x=1728395838; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=B4jCmXmpS2iZoImmfRieVfG5HdqwH8Az+syaaeoOy6U=;
        b=dD7CDPLPARMBo7aqOKNTR0/FZzyGqrPjWQ3sbW45eilT4O/79MUsYoxnVqWBb4l6Hj
         tGIEWR++aKHmCPIF3F+2N4nfbExo/VCgRL2EpNsh8MVJBj7/W/7kXJ7MGUE+p5pCzq/V
         CG8bkx2p9PYTVNUOAwekWkCCYiQRrdwPf24e29MfBz+o9LpRdBsmT0THE/8ojNJJ03uc
         4fdo/dehQ8J+Dm+IbxRFsvksGBXgZfqmkvKtMfweqSu1+GTGdw7pAh/oJy1PfdQY19uN
         72WlNDCKx5erKO0IVEniVLRMo3ZV4XoTtxIZaDE2xti94KWxj8odhGX6/UcswzQ5OmO/
         /VaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727791038; x=1728395838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B4jCmXmpS2iZoImmfRieVfG5HdqwH8Az+syaaeoOy6U=;
        b=bzFb2CVQzGKVhrlLT8RpRGw33OVpFzL+U0tfPqDnb9riVXAPJpvonOWnWspxLg4wLN
         WQx4G1Q4ElWCDERlSubMfhmBxkyC1AaqlVhPQdBCe9nIMREIa4insQV6sd+QbG+xgTHG
         Og+NKXpAaQMWPAviG1qADN17u2ezgrq+SQP729HM9FBXuJIdQQ0Qft2kuzRFHX0MATcX
         BoA20H+f2G4qSSWsckD8sLhsVBCKbM9iRDWlp/N3SIzTqXrzbYDh20daoOcQz15w98qL
         yECMEusRRKrdNxmJCMMsbf07bnKVBJYJ15vPdfa90ZCv+XN4mhWIatTJnYKe3TmDUBRU
         XiDA==
X-Forwarded-Encrypted: i=2; AJvYcCXrpgvkf3Q+VcwUCfYPqmwJDcXKCWd3h954wLIknWn9vsIiFYY1+6nrJxogWHcIKnjo2KFF/Q==@lfdr.de
X-Gm-Message-State: AOJu0YzM/taMxfhBJ9QkFgmJ25ZWiUX6Vx/CC2XCvDimX0WWJzjk5K/a
	LZ8QxdOzrJ9H07vuMJMJrH9AJp6FzbeeTesm6IUq9WRs2v2244lg
X-Google-Smtp-Source: AGHT+IH58j9m6DSfAsSwW0Vitrba+N1DoVsHbV+q7M3UlD+A+Xb9Yl1q3Ozj3OrwXNL7U9qRipfQDA==
X-Received: by 2002:a05:6214:5d8f:b0:6c5:50be:dd74 with SMTP id 6a1803df08f44-6cb3b64cb65mr230584956d6.45.1727791038489;
        Tue, 01 Oct 2024 06:57:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5d42:0:b0:6c5:19d1:7aa8 with SMTP id 6a1803df08f44-6cb2f120891ls28109396d6.2.-pod-prod-06-us;
 Tue, 01 Oct 2024 06:57:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdw48C/6hGjWuxrnpPVYueQDDXsDOzMhumWX8DmNSQGkJeBrfCaKDbmVmwuH5h7HfRjzYXBwapxtE=@googlegroups.com
X-Received: by 2002:a05:6214:4883:b0:6cb:7f2d:b0fe with SMTP id 6a1803df08f44-6cb7f2dc293mr9025776d6.19.1727791037677;
        Tue, 01 Oct 2024 06:57:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727791037; cv=none;
        d=google.com; s=arc-20240605;
        b=XVyhkxWJEQj3sUPVdiC6n8MCQoesldU64q80ACnaJ8ktHfQ9hvOAKM/x1WvWC6PmC4
         UvuNZayiurxTd/JvLlCApaSOLJkqqK7dqjmDS57YD4lOPVz4TPM14cv+zXf4K7JLbMeM
         BzP4F0R1g865gp97LtogfonBVEAIU25WG1G/4rrFb6YgAGWcpHTv6N9R7pcCXn1BaTXt
         9WrVMPFZ5jytnCt9/Qoos+TfM9J9MiFCA/l3UDvGrEilAclbuIYjZkrgmxJe5ZBuFw66
         fVEy0wxG/2V6nkWquOgVqiMXdcL1T5E99dp6vGqNfirA7B27BWOFXlv/mQidJEG+VNPm
         9VCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9PFAbc8gZj7FEr67uMmDVJNbst4qOOa2vLXUqiM1p3I=;
        fh=uimhvXIa448I3sZnvqBy1E7XnpLzba3I4zkEKtTh22U=;
        b=BDPQ6Ok6V0J7ve2LOz51frVHA0+F2KVf2zAsUk6zJt2GvMDUgZimqOBGyro8w/rEXV
         qk4c8e6wEXlH5J/PoEyCmNXqqH5G5HHvtvkyn7Ov+Wim2/TUhgyOvEv3Ra3jDktgd2KW
         ta6QR1NNk+GcoDdlvbDs4fWHoctsy9rl+57jZtMVsVH5wsMzuFl+E+YnfIOU1XfrMNA2
         1vIOGdupZPTUcjx7uYIvslvBprJ0T9b6XQoHqL+Vb4+Hm7466YgKdFd13QuRcrhBhUI3
         NvELztrZdQ2O8MCiBf0vIKh6HpAnzdod2JBdroUwzDkhFgSySli5jakvwRWdN56GjP6M
         J0hQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vpD/nUMy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cb3b6e26ffsi4489896d6.7.2024.10.01.06.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2024 06:57:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-2e0a950e2f2so4418376a91.2
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2024 06:57:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU61UDcy5N62yrtIjGIlU1WJxVP0xc5Zewma6wkam0WlQ2l2VApDM7a+lnsggNf2OkOFbDvHCn5xjg=@googlegroups.com
X-Received: by 2002:a17:90a:c691:b0:2d3:d45b:9e31 with SMTP id
 98e67ed59e1d1-2e0b887c870mr19277418a91.2.1727791036665; Tue, 01 Oct 2024
 06:57:16 -0700 (PDT)
MIME-Version: 1.0
References: <20240925143154.2322926-1-ranxiaokai627@163.com> <20240925143154.2322926-3-ranxiaokai627@163.com>
In-Reply-To: <20240925143154.2322926-3-ranxiaokai627@163.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Oct 2024 15:56:40 +0200
Message-ID: <CANpmjNN+Oq+U9V3v2hZ6g-BoLXhm-PS2Z0dU5NUCdD+CRuhO3A@mail.gmail.com>
Subject: Re: [PATCH 2/4] kcsan, debugfs: refactor set_report_filterlist_whitelist()
 to return a value
To: ran xiaokai <ranxiaokai627@163.com>
Cc: tglx@linutronix.de, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ran Xiaokai <ran.xiaokai@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="vpD/nUMy";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as
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

On Wed, 25 Sept 2024 at 16:32, ran xiaokai <ranxiaokai627@163.com> wrote:
>
> From: Ran Xiaokai <ran.xiaokai@zte.com.cn>
>
> This is a preparation patch, when converted to rcu lock,
> set_report_filterlist_whitelist() may fail due to memory alloction,
> refactor it to return a value, so the error codes can be
> passed to the userspace.
>
> Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
> ---
>  kernel/kcsan/debugfs.c | 18 ++++++++++--------
>  1 file changed, 10 insertions(+), 8 deletions(-)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index ed483987869e..30547507f497 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -131,13 +131,14 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
>         return ret;
>  }
>
> -static void set_report_filterlist_whitelist(bool whitelist)
> +static ssize_t set_report_filterlist_whitelist(bool whitelist)
>  {
>         unsigned long flags;
>
>         spin_lock_irqsave(&report_filterlist_lock, flags);
>         report_filterlist.whitelist = whitelist;
>         spin_unlock_irqrestore(&report_filterlist_lock, flags);
> +       return 0;
>  }
>
>  /* Returns 0 on success, error-code otherwise. */
> @@ -225,6 +226,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
>         char kbuf[KSYM_NAME_LEN];
>         char *arg;
>         const size_t read_len = min(count, sizeof(kbuf) - 1);
> +       ssize_t ret;

This may be uninitialized depending on the branch taken below.

>         if (copy_from_user(kbuf, buf, read_len))
>                 return -EFAULT;
> @@ -242,19 +244,19 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
>                         return -EINVAL;
>                 microbenchmark(iters);
>         } else if (!strcmp(arg, "whitelist")) {
> -               set_report_filterlist_whitelist(true);
> +               ret = set_report_filterlist_whitelist(true);
>         } else if (!strcmp(arg, "blacklist")) {
> -               set_report_filterlist_whitelist(false);
> +               ret = set_report_filterlist_whitelist(false);
>         } else if (arg[0] == '!') {
> -               ssize_t ret = insert_report_filterlist(&arg[1]);
> -
> -               if (ret < 0)
> -                       return ret;
> +               ret = insert_report_filterlist(&arg[1]);
>         } else {
>                 return -EINVAL;
>         }
>
> -       return count;
> +       if (ret < 0)
> +               return ret;
> +       else
> +               return count;
>  }
>
>  static const struct file_operations debugfs_ops =
> --
> 2.15.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%2BOq%2BU9V3v2hZ6g-BoLXhm-PS2Z0dU5NUCdD%2BCRuhO3A%40mail.gmail.com.
