Return-Path: <kasan-dev+bncBCMIZB7QWENRB6VV667AMGQEDFE2KVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A1C5A6C53C
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 22:32:45 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-30bf67adf33sf17380911fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 14:32:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742592764; cv=pass;
        d=google.com; s=arc-20240605;
        b=A0qIV8gZtQkYhOC8Y5jpPrdjVDIZ+49izQ04wlWWqW5j/ZPQqDFb4UCZ2stS1xIVKL
         /H6H/tl1om5mpOswF7A8aFvpYQcXCw9d16B+GlrNpmfxVm21/cXikCMXxE5/hqbml0ZT
         cOXswHstIckILA3HEaxbom0g1C+ICoHpSan/d+mmI/ZyONIbRKelLwV8YuWdbcChHpGM
         UtdK//tscJQMGP/gBUKlcFKvirDz+SanQFAQSuyUdeSOINQTwP1uXgS3UK4yEKnBDUi+
         oU8PpASpJqCjKapcm5Qp7OP6yCOev6x+SeO5lKxPIK+/JtZNDoi7imrJ3S1JAGQg54Rv
         d43w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FFEebyn68BuN4Kfsx/mlFDQCemBBowyfuNllsd8adcY=;
        fh=n214Hkjx5ek0KeqQ8fcYFr1zaZCXxII5I800M4ue9YA=;
        b=IEJpGIkcXIy6NtvipaXMuuLRye+egLVwkwzJRpkGUI8yDrYsY+l1H7AN8qPzqc4Q58
         AWg7Z0nBQwGT2vxiSDEoxTUJHBwQjMCzAyHBidVM3mgN1WTFCPU/9oJ+bnP2rVJoUS6+
         26gyIy5BM7pA6eEN9NV73ssU8a26Ms5f7UIFaNJXPmCGHkkt/B7XrYG10dNM7MeahSZE
         xaV9cVMX29+vODz4AphOosnNhsWItZEY3PLdkUZYy/NFDJlur6kR4vfIaUp26D4gIzFR
         zLH0XyVkaQCL/m/fk023pQSOqV9tsqDZf1wZkyjXxCyzoZ3NfcKod4US449mt4jPg8JQ
         hT9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nOb4St/G";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742592764; x=1743197564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FFEebyn68BuN4Kfsx/mlFDQCemBBowyfuNllsd8adcY=;
        b=QAci3xz+q+VMToN1m0AnNuwQs6fgEaJpfJFG7yiIa/lCnOXuFWqwRIlX4SKoOAG5gh
         KF41YddkQo/rueIjUPOSJuj5/OzEi16lBGQvw3Ja9mQyWbUAFYHcinHJu0psr6/VSKyI
         sqsrFRVsobnFVsQHtRzQarqAoYR/+hsaGFZSzkIsvsus8jcIsy0CJLhz6t20dg6ANNej
         sx+10QIN3vumbTu6o0+2Q02TizIoa6qdgn6BB6X04gJUKKVNNilrwBI5Aqmoj3H6Zp4g
         gP0tBk0sGzPbappuEkkRcb/xscc17Y/MdiH6jx+c3mC1pFmF+q3iZ8ULnLLEirhDUjsO
         qqsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742592764; x=1743197564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FFEebyn68BuN4Kfsx/mlFDQCemBBowyfuNllsd8adcY=;
        b=U309E8p5wYtc7ZMZr5uQ5uh3RpIuLDH3CUo57xya6hvqJ+QOPgqHFp1ULF+AIGYlon
         uGeQnZ+eN6F6dVkIcip3gFuKxz5mXjGztlGA9NdDG8atZV1L0JEzCw3FlPKcUr2w0nFL
         hXq/1PJdkSkcDcqbmQrjx9JSopDieQvM0k3mpudiM6R3iOtBuZ6MGnCF0ZVENGMBW8ee
         aqOWmVBPJZZCIXN68Fe/GtNsfJy6UKYtzTuUrksgJd/dc6v+0d6cz9iTPE6ZAVeNtAFh
         mSYf/1BdGZehHHOBnPXC6XXL26WecCSdAcDJrtADB4ptz7eZuit/D7FRprtkE+HHug6A
         36zw==
X-Forwarded-Encrypted: i=2; AJvYcCUt+duH5YcM7veu7OazzclMyOBI/4UugM32w2wk71s1sNZabqQ92188RO43CBaNe/hvyyZEhA==@lfdr.de
X-Gm-Message-State: AOJu0YzRWhJxRXxD++OoFI9Mi3BZuDLJ06tGR0H3vvU3nPS9vfVC7Buy
	zYmH1tXiEZxNgjjylWGPbN4tzDya4isUxVWQTbEOwjM5dyvRxmuj
X-Google-Smtp-Source: AGHT+IG8kB0hfLEjCovFEFYQa69QlCn35EvMqOkx4QN9F+iBVROhvUqelnmH0MffnBa5tIbxgfE+Aw==
X-Received: by 2002:a2e:be93:0:b0:30b:c36c:ba96 with SMTP id 38308e7fff4ca-30d7d8acd00mr22769821fa.1.1742592763514;
        Fri, 21 Mar 2025 14:32:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJzWGpt11I/fco1DnYcig6Hv+Aic0HtNaL3i7alKcFSxg==
Received: by 2002:a2e:900c:0:b0:30b:eb0a:ed6a with SMTP id 38308e7fff4ca-30d727627dcls1178021fa.0.-pod-prod-00-eu;
 Fri, 21 Mar 2025 14:32:41 -0700 (PDT)
X-Received: by 2002:a05:6512:b96:b0:549:8537:f337 with SMTP id 2adb3069b0e04-54ad604dde0mr1929704e87.14.1742592760767;
        Fri, 21 Mar 2025 14:32:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742592760; cv=none;
        d=google.com; s=arc-20240605;
        b=RN1Pc76lN3tx/sSRFRG2mf3e9BIHbH9tXsLdtBToXSjsw9ZIOal3v6WfrlUe8EXU/b
         +5YZgREiUUZSfZ7hpcUI4zvnX/eiGq+6XherSXwON2ap/l9BWj+tgGUgNI2Rv6c08/nq
         Xo8KhbycyJS/geXxPNVB3HtfE2ybqrqT6w6UvRWHHp7VokgzR6Zm6Xds0V6RRoiMGKpC
         JosqvLJOJf+JQ1RrcgSFtyBPgvWc2ni/SvPcX2EKugKG04A9IH1b0MrD5gNqBcPN2eRj
         Z6Dlx6QoUQnHlGxlxg4v+Dy2C5HoS2O6c0cXA6xUDg32XPV7GVezV5ev+eVqZES0s2gU
         Ms2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1cysb0CEngBrXdkVI2Y1jsaTpmmNgyKtc3TE1oqQNkY=;
        fh=UUJWo8Ma3B5UGDWKm3OF5Xw15eOZ5fw+l8DPF4oDpZk=;
        b=gNLmlMuvYp9kxldFOoKrCGDdJKLiuRqnf4sddeDV8ATzy4+DhFaFlfT9LpPIn+cj2E
         KUa/vgil0f+oXr6NkijSne9FraMojirtR+nG68J876cibehbC0OSCAZ+4pn3oBQDB1Fg
         dESM5bW5JF7E37EUNqlLMD27AebHVWaHFiP2F/bUnL30l2GJ8lKJIqnQvWkks5Fy3Lgy
         q6a0+pl7ROUQqhAXZs39vLtgZiR7dLbhYM39qYJY1Mzpa0np/BdUWIpvKqWvDjrQW5kZ
         4m8IUKqHUUI7opPpI5CRM70STc/mITYBjtFrSEaAYjb5QFRdHZbEJm34TZsCRjJ7quOV
         CvPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nOb4St/G";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54ad6536a00si44873e87.10.2025.03.21.14.32.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Mar 2025 14:32:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-30bf3f3539dso23390621fa.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Mar 2025 14:32:40 -0700 (PDT)
X-Gm-Gg: ASbGncuUPJdlX15hQxpXZjrdxwgXuzDD3h7et+gom2kNyOxO70pw5mVRgjiVebFq7rv
	p5xdRv6loyR7ZiWE2G7wSMxu46rymRAIkrT5FUC90hN6jP75nHtjAaODaYvTssDI02TLXjxScLe
	kSBamvFOKyzglFnTjgjM0o+7r+0PWrdLGSQT+vwnhteT/ToOjY27tFE9Q=
X-Received: by 2002:a2e:96ca:0:b0:30b:f0fd:5136 with SMTP id
 38308e7fff4ca-30d727b936bmr38994891fa.18.1742592760129; Fri, 21 Mar 2025
 14:32:40 -0700 (PDT)
MIME-Version: 1.0
References: <5vpovh73ejzfodl2gpdx7hqr6d5tssivk3q3ibqx7do7gqwwam@pgx44qj76bzr>
In-Reply-To: <5vpovh73ejzfodl2gpdx7hqr6d5tssivk3q3ibqx7do7gqwwam@pgx44qj76bzr>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Mar 2025 14:32:29 -0700
X-Gm-Features: AQ5f1JpCtCiKhQzY0ozrnLWtv8GKNcRZG35CeJ5E9nD--zZhKpAkUutXtaA2Bow
Message-ID: <CACT4Y+YR2XBhGmjAhOEb=YdE4k1cSHzNKtqSdDcCP6znbh4myA@mail.gmail.com>
Subject: Re: KMSAN splats with struct padding
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="nOb4St/G";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 21 Mar 2025 at 08:47, Kent Overstreet <kent.overstreet@linux.dev> wrote:
>
> I've seen a couple cases of kmsan warnings due to struct padding - or in
> this case, no actual padding in the top level but a lot of fun union
> games - which are probably treated as padding by the compiler.
>
> I was under the impression that compilers not initializing padding was
> getting fixed - is that not the case?
>
> If not, perhaps we could still get some help from the compiler in the
> form of a type attribute?
>
> BUG: KMSAN: uninit-value in bch2_disk_accounting_mod+0xcc0/0x1c30
>  bch2_disk_accounting_mod+0xcc0/0x1c30
>  __trigger_extent+0x5a5b/0x5d20
>  bch2_trigger_extent+0x7f4/0xf30
>  __bch2_trans_commit+0xac9/0xc2a0
>  bch2_extent_update+0x450/0x9e0
>  __bch2_write_index+0xf53/0x2810
>  bch2_write_point_do_index_updates+0x55e/0x940
>  process_scheduled_works+0x7d9/0x1580
>  worker_thread+0xc17/0x1170
>  kthread+0x9c6/0xc70
>  ret_from_fork+0x5c/0x80
>  ret_from_fork_asm+0x11/0x20
>
> Uninit was stored to memory at:
>  bch2_disk_accounting_mod+0x17ad/0x1c30
>  __trigger_extent+0x5a5b/0x5d20
>  bch2_trigger_extent+0x7f4/0xf30
>  __bch2_trans_commit+0xac9/0xc2a0
>  bch2_extent_update+0x450/0x9e0
>  __bch2_write_index+0xf53/0x2810
>  bch2_write_point_do_index_updates+0x55e/0x940
>  process_scheduled_works+0x7d9/0x1580
>  worker_thread+0xc17/0x1170
>  kthread+0x9c6/0xc70
>  ret_from_fork+0x5c/0x80
>  ret_from_fork_asm+0x11/0x20
>
> Local variable acc_inum_key created at:
>  __trigger_extent+0x58e7/0x5d20
>  bch2_trigger_extent+0x7f4/0xf30
>
> Bytes 20-23 of 64 are uninitialized
> Memory access of size 64 starts at ffff8881d998efc0
>
> for the code:
>
> bool insert = !(flags & BTREE_TRIGGER_overwrite);
> struct disk_accounting_pos acc_inum_key = {
>         .type           = BCH_DISK_ACCOUNTING_inum,
>         .inum.inum      = k.k->p.inode,
> };
> s64 v[3] = {
>         insert ? 1 : -1,
>         insert ? k.k->size : -((s64) k.k->size),
>         *replicas_sectors,
> };
> ret = bch2_disk_accounting_mod(trans, &acc_inum_key, v, ARRAY_SIZE(v), gc);
> if (ret)
>         return ret;

Hi Kent,

Do you mean -fzero-init-padding-bits=all
https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dce4aab8441d285b9a78b33753e0bf583c1320ee
or something else?

The commit says "enable -fzero-init-padding-bits=all when available
(GCC 15+)". Can/should kernel code rely on this being a guarantee? Or
is it rather just a security mitigation for some compilers for cases
where the code is buggy?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYR2XBhGmjAhOEb%3DYdE4k1cSHzNKtqSdDcCP6znbh4myA%40mail.gmail.com.
