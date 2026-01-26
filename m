Return-Path: <kasan-dev+bncBDH3RCEMUEHRB27W33FQMGQESI2VXII@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uLw3Jm27d2lGkgEAu9opvQ
	(envelope-from <kasan-dev+bncBDH3RCEMUEHRB27W33FQMGQESI2VXII@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:07:25 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C5F08C567
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:07:25 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-6582e841d15sf4570138a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 11:07:25 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769454444; cv=pass;
        d=google.com; s=arc-20240605;
        b=Of6JwKRTly1itcwjmwmr04uVAaB93txk3v/wc+edEUS4vzh+TlGcizmg5oXcIprNTB
         g5UVUfLTzFvkrx3RceKEu6CV4sq3mS/oRThOu1nW6MvZ9srDMtmTE6mwctPL03P52r7v
         D9OnPzYXASOsb0TnkNvNa//dIpdiCUEFsdNxFH/33dQDOlhkUU42Ow+x6A2+i5MjEfTv
         yonChEz+IcTpcELGtnSWluCtHW6PSkjLs9njeNS6M34NjN7n3+POP9hZNy0arYPLIZFe
         7mC/Onvq9tVTxxARFYL6Tv39L2JWhpI5cTnizcwIsec5131IAURUQMTAWIcTRbklssLf
         NJGA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bNDmp9cXZ+CKIYR+0UC+w+kePaIfoUIYx6JXoWkTlso=;
        fh=qF/qulmQ0Ox1wZeOzhHv5RCj1GGRPbp375zk9aZSlWA=;
        b=LCH/RkgIHu9glNxtA2hTznr9bFwhEoV2WRF9VvPqYdl5QRo0PMoxdWqtbPQTEPLFmQ
         9YzRS21K5YDAviHoxIfaYcQpu+A5Ezu7K5UyZFFfHDBd5Z15hGMxZ0H4HNpJbJ61nWGC
         hgBt9/voBVdHKqkiM3iaPxlET7I2lWataUMqwMWahdUi99FBTST7SGpuJg2Bvtk/DZ8a
         PF4y2y9KeZh6ZIj/CGbh0kH6ExQ+IwFzxnCCQCe6JRJ1XEEnlbbJ5PNbn99gDO7utv8o
         8VqUqjoehzG56+HdKB+MWSq8B0Qo1OoSalX1JyYrwUUH/JvKSRHl6myOoVCiDHShb8UQ
         U30w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="l0e+/jse";
       arc=pass (i=1);
       spf=pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769454444; x=1770059244; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bNDmp9cXZ+CKIYR+0UC+w+kePaIfoUIYx6JXoWkTlso=;
        b=ERbdxjb+JOVh5QCkCCfM+pdcxv9xETarrAGcPqVt74uryFQk0pPScaPN7w/vrc8IL0
         Wq1994EIy25UlgC8gse/be7EpuFt2cTlh2VfEUvDyei0b39cuOxgRrVHpmKgIoJtMmPV
         7wCx26CKe3NRY8gRz+amjdjvPr7Q41K8ks4zX6lvcbkvLv7bJije14c75ENPIQcw7IjF
         uPZ9EcYsrwg5P47mZMSufJJk3pAsxoKjGJiz1xAlQ/7MVI+6tiGHsnBVlctIClyv2u+G
         /xgkYnHR42V9W7V8ElA37uLME0jAkApCPcpe4JPbw8tPQ0QJhOF7GN2+aJqe2xFS9OUE
         tG6w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769454444; x=1770059244; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=bNDmp9cXZ+CKIYR+0UC+w+kePaIfoUIYx6JXoWkTlso=;
        b=GSQh3EVfO1+CqY9TevRVhHXxEiXmPe8IABPRilAc1bKEz6x9VMoGZJ3ZKKwD+HavVi
         ycbk6NtrZhuf7YGKvNEOJ0c+5WUmWhAJSo1gYxwklLp+BH/zJ8z4y/ELrjxpmMSJXPLJ
         3Nl1+sbW6PwXRGzxpjONXbcOYRpLhEfoR50PO/MA8jmLO0Khh8nD3YGZRJc8a/a8a2le
         woozjJhhLRt/afzVzmvwJNzMjMq95sKoX51kufaxUcl4mjdcvzagdFqUvHg/zlKOoNYa
         f4CgATIFJFkdJpiReBIanImzBs3V7QOaXC0XUE/NSaa/iPqdmmHDroMafMRO3bvk1AkM
         Wu/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769454444; x=1770059244;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bNDmp9cXZ+CKIYR+0UC+w+kePaIfoUIYx6JXoWkTlso=;
        b=l19xlyRP6R7WV+wp2BO3/9de7VUijVAJ2bZTD7ZOQPL1tW6Z95uduoh8KUwH5pmYik
         YegHMCyEka8KP9S9WqejtddrsnPoh05Ck+NaTSncw6fY95bQBS9v2H6dOjobDwQDbq93
         xz5r2Fn7LRZ2Ky9FVgh1RGpzD8DuAU2/YeLN2/BG4yFTY84Tz5ZicXTa+umBkipmgVRh
         5h1ezvVTWPvsT2xy6hGMEOfrIad2KG2qVYgP6x4y8JfdRaf54a9ewQRsVzQMSnvrFnJt
         Xq1eJO3qMtHLE+UjrdZDJQHMNoDa3D5GZEv8qroWGnT+A0pA05qTCNw4XhWopyPS/KY6
         QhDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWDNCCZCbefmKuEpTtdUGRkG8EzKaOdks6tJQu+pqC94/8FYsZdXaxvgOym8yfJa2vYWM+M3w==@lfdr.de
X-Gm-Message-State: AOJu0YyRmHBnnggvjZ9hkLcrJaR5zoNF9t3CVFbKMaU7FlmBJGTkAATj
	oG09fncxARHsKAiyquz9RQG5S89i2O6LUg+ud3ySiC84ERE15jLeq05R
X-Received: by 2002:a05:6402:84f:b0:64b:7e89:811 with SMTP id 4fb4d7f45d1cf-658706b2fdcmr3615230a12.13.1769454444369;
        Mon, 26 Jan 2026 11:07:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Edkd90AUjJsb3XBjj0Hu9RLgg7wDjqmr0OJWllUXBvAw=="
Received: by 2002:a05:6402:10cc:b0:641:6555:a42d with SMTP id
 4fb4d7f45d1cf-65832d6d237ls4109138a12.1.-pod-prod-06-eu; Mon, 26 Jan 2026
 11:07:21 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWiGXBiSsfiu8euD+y5TjqkM0bPKMxx1oi3YFFgzFXaH3xG08ePSwDZdBYMToGwkxKlFmDnVP4+OvI=@googlegroups.com
X-Received: by 2002:a17:907:96a5:b0:b7a:39a2:7f50 with SMTP id a640c23a62f3a-b8d20e3f050mr341564766b.39.1769454441713;
        Mon, 26 Jan 2026 11:07:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769454441; cv=pass;
        d=google.com; s=arc-20240605;
        b=b0RyfNGk0yxNUoGBAD/tNIoPNmUcU6LTnVpgg7dqzfDEB5dHIK91pM5zjCIGVrMDXe
         xceRD6K9ckH+XtYQfd2VRwai8w+Elzzc6RLuSYczvfNFu8U+s6dJbEQImIFa+dIUg6qV
         2K3SJEZ67UTrH+GhjunocuPxrgNtBMc7r4oMEJauBiddxJ1OTymT7m2XvWThiYswO+Xz
         W/ZFNgGhZiJe5uKgY4TalvkIy+BK7YZgzvJqumd923VFQOTb1YhSt0fD6DKd/YCG4OGy
         YM/NsS+iDUX+yM8174X9HxsXSz50Vg2kguJrRx1nnROZy/Ge1QAFau9M5zDZWNOI6a6w
         2xpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fwcJVr2q9L2Rbh+quwqtL6yXJS/M0lAMvjR9C8tF+mA=;
        fh=oyzCquBlhRIcMifDLUMYYUqG47zdRbRdoEAXgioSZnY=;
        b=QuZGcX9zj3segVnkx9z0Pt6SVZs9VSfl9vVEquFPbki7z6wzftUBcE1srwCkgGdnUh
         1QRxEqNA94E4WmfQPk7gxX0HVCFGWR3u5RCPwsdC5Y0XzmLd9AD5jNY+zAvTC1qeMO0/
         pcY5o6+EqgVg3LpVLWSXxNkn4xdgKJrGJPH9SRai6aiLNRUiFYXUpfmhdll4ywbFpoXC
         hlRv4BLHllluGLxusQKK+mS3wc56x2WXNoQXfrXbtoN8xnIR+nmWe8T2s/FSArYDd0c9
         dRyQwANgoxExeVRHYW6EkH/mWDAdK7ehiaD/CWqlOOpD0BYR7tgIFqn0u6e/grRwbm63
         Hl3A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="l0e+/jse";
       arc=pass (i=1);
       spf=pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b927e43si237132a12.7.2026.01.26.11.07.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 11:07:21 -0800 (PST)
Received-SPF: pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-59de38466c2so4934859e87.0
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 11:07:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769454441; cv=none;
        d=google.com; s=arc-20240605;
        b=Xm3H9Vm/GLro1G0eNi5Vji+vsOsohTV8RRU5pmfjI/2g8Ot6z9ZBapcl9rljKylVm0
         rN6sZxwoNBCy8jXeb/zghOyssJIwl+m3iyWbv7HlO1QyN6TvVyG94L8+vlDp0ToNTFbF
         W4k4KbvVSDnS21+U1bSeqNsFyWjN4vjKMqpMKr6WUwwKptlYSp6rtCqnTpShVrbHbAJZ
         f3qg8lR7elZZBdj/oH6iC89zGm4UJc2+EGHgluZ7ogDHzsiNDC0Z1FU872H8UUDUg0Bl
         RxpVFsrvdRAGaQ6jMCQ6pD+pd5cB0Iwp6XaqeQRxJzYfm+P3w8YSd/+Chbos1XwUQxvm
         QUTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fwcJVr2q9L2Rbh+quwqtL6yXJS/M0lAMvjR9C8tF+mA=;
        fh=oyzCquBlhRIcMifDLUMYYUqG47zdRbRdoEAXgioSZnY=;
        b=IWsG4CWheFnYca4wXzE7sGlCf9g5Qy8R+qaCbnWyvhCsQBazs01W1F++rSBV8Ybsyn
         Ji4xdEZiWAx4mSXt+5xMXgWMA4wSx1IHy0xgiVyaIDbM3gxmejFzprBwD90rh+I/YtlB
         kkBZ4bbMpxfpf0fMz72Peea90fQDpDUr2/d38IZjrquYd9bMRESEEsYxAkhyJHshXui9
         7UkBzepZJM+x1k3BaHyFEjbF7P8S4FFhgbYaf0hmeIBFoN61OuBB6bIeDJ632uVU4BFq
         Wzndj7I+1FgdpjMq6ETLtBTzep1vgAxkBpkOZIs4PtMjN+QdGrge5adE9VfXIjxjQXD9
         TRjA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCU0/nN8zL9wmKjAoyU055VA/yuC1myqumg/t/HU6oUtQuJGinOxDBWb4dK9Z4SxnEYLS3FfjERul1s=@googlegroups.com
X-Gm-Gg: AZuq6aISdWD4ebBoyapNFcBIBt1iZn+qVHTP0YmnhkYb2LrceB1wAQoZhGFhz5XN3rp
	QcioMIZ7QrNpj+exefmL8Id/ypgqoKP4JzB+n4JqMgrv9ALNxqH3pIhKJvbOTNnNy4mycIBW2RK
	JAn6L7JyksNN6MHjuc20iPxdoEBlAYUIXup1SZwJLzhfVRBjtBFs8OXP/yqDscGmIs0g1oRKskW
	xVzWNKe4VYo5XOEklfmIDCvp52p2N/VyaUn8io0xiZnVNeJkkz1gqdfYn++OllNL2yN+yd3
X-Received: by 2002:a05:6512:1387:b0:59b:b020:ebaf with SMTP id
 2adb3069b0e04-59df35f7f1emr2016689e87.5.1769454440656; Mon, 26 Jan 2026
 11:07:20 -0800 (PST)
MIME-Version: 1.0
References: <20260106180426.710013-1-andrew.cooper3@citrix.com> <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
In-Reply-To: <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
From: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Date: Tue, 27 Jan 2026 04:07:04 +0900
X-Gm-Features: AZwV_QgggbAh9r14pvgw_QdKmtDm2tyV7BpejT2mYdhLXBUutoMRtjgLpUUq4pE
Message-ID: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
Subject: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: konishi.ryusuke@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="l0e+/jse";       arc=pass
 (i=1);       spf=pass (google.com: domain of konishi.ryusuke@gmail.com
 designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_FROM(0.00)[gmail.com];
	TAGGED_FROM(0.00)[bncBDH3RCEMUEHRB27W33FQMGQESI2VXII];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[konishiryusuke@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	MISSING_XM_UA(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim,mail-ed1-x53a.google.com:helo,mail-ed1-x53a.google.com:rdns]
X-Rspamd-Queue-Id: 3C5F08C567
X-Rspamd-Action: no action

Hi All,

I am reporting a boot regression in v6.19-rc7 on an x86_32
environment. The kernel hangs immediately after "Booting the kernel"
and does not produce any early console output.

A git bisect identified the following commit as the first bad commit:
b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")

Environment and Config:
- Guest Arch: x86_32  (one of my test VMs)
- Memory Config: # CONFIG_X86_PAE is not set
- KFENCE Config: CONFIG_KFENCE=y
- Host/Hypervisor: x86_64 host running KVM

The system fails to boot at a very early stage. I have confirmed that
reverting commit b505f1944535 on top of v6.19-rc7 completely resolves
the issue, and the kernel boots normally.

Could you please verify if this change is compatible with x86_32
(non-PAE) configurations?
I am happy to provide my full .config or test any potential fixes.

Best regards,
Ryusuke Konishi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw%40mail.gmail.com.
