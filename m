Return-Path: <kasan-dev+bncBDIYVEU5R4JBBHXNZXFAMGQERKFWKNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id C02A8CE8D3D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 07:52:15 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-8bc4493d315sf2351068485a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Dec 2025 22:52:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767077534; cv=pass;
        d=google.com; s=arc-20240605;
        b=H0QW7LsqG6x/uc7nOyt5KH1DtQJ9kGnGHxBLNALTPMRqLBxRaAhpr5aNqMlBKe4MAy
         zT+NEisjdvjM4q/mg9mS/6h4EuOpJulDB3sxMCPz/hPa+djyoTcRapl5Y5AcqFXrC7Dl
         1Vm053+je7KbiUoT91HKyYf+K0XRkSym3ApKSoZ+zFllMXZQrmf+3HVgXsqlFMPHhT7O
         Ni/wrafV5i3oYVeqdxwUP5NhLowgkEF9IoyS4SRP9VG5AyhBXI0YeL0ma2EqqHNPQvTW
         NEgSioKE1+Z46K6tNplLBFxrwfaiSlxoVro/3v+kEu7Xyw7RgaRTTPct6Lx65dhjfxUf
         ZVwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature:dkim-signature;
        bh=VBnZJZDGhdRNGBjMDRL9eG9GcLcP9jl+sUTup0CuxvU=;
        fh=NlcJpG5FhdaMiQfcwmASQUWMz5BSF9gqhLkiAiIYkRo=;
        b=NQJYEyVWmCVg/ajbraDaFommzGS/0dD/S/WSTetKlZaH295pzQkWfNCVqycoUtmUey
         xvl54XxZ4NLmgwuD6X3G3s/M7kEqs78qrbDQcM91hMQw1+6RxI3Td3xmakKmv91BnTz/
         TcWnoRto18mT02mK98fc7UjokibOvH4nBiWgCH3ua0jur/JGo0M9Hjewno6fQoHgUocz
         5rgPMk/UMI+B8Iv3TLsY4yxA5rLqIAe25xc/k4Br89lWu4ZFrzP5u0wuEkx9F0cV57g9
         1z6yEGYrGVLXB+8H9mY2djjlGQM6ebL3BgbCURCaOoBzsx572H5lt1OIawYeElkxqFdb
         O6Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JmO9eH9o;
       spf=pass (google.com: domain of eddyz87@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=eddyz87@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767077534; x=1767682334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VBnZJZDGhdRNGBjMDRL9eG9GcLcP9jl+sUTup0CuxvU=;
        b=fpOl60WNdt2/AxMFdPa4aCXU/FGo28dAvuVEOxmyPGJedhOwHZUoFafXjb6dIZsKoB
         5rFFeVWATKoiLcHDCIPecRt/7BHJQ4cBmR+zTNtfGDSbvoARLi4jpmVc5WHcQnWlXzTM
         txvoLJonV4Pmu9iKv+D1Fhh41zbpCo9JQz5pncwtws1F2svznNnfVhgzn3yc35b+rbp5
         PykteRJ9C5nN7QODGI7TlmkeV4pmZWsh8GIPOwBeQCpH0ZRH+ODj/lluMvvCK3+Z26ED
         9MBzTk1bxmqAlUXnuZR29FSmIw/wdNxMAZ/QAgNx4qyaDQXHrzamMooUrDMQkJeEMhpK
         IUvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1767077534; x=1767682334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VBnZJZDGhdRNGBjMDRL9eG9GcLcP9jl+sUTup0CuxvU=;
        b=XVIOzf7lf2fyCKOFxhkZ5hPlJUQIfQoBtKRf4DsO5SvGSwPLW+BX5/3vuZb7Cfan5y
         XxEOprDDIdH3mAWhO6b/6diLA4O20VNfxkhZIi12clWH34p00v65a+qyacvxb1DT+mbJ
         flbG7EikpfgTiSEWL/1yk9gujhGabRZI+fRuJTRgK+161kDOqGYkyffphrnblMaCnY0I
         cMZSOKqef8agobwNhh+XiQaDqIo/UKOCxMeA0VDo8fIYfdGj2XpQp26/Z3MJsH25oF0K
         h4XdERKsFAQwh+1wjmJkNvxMEK0JTsfZ2gSJYOjPq8oGRfxQkaGLTO3LoMpcMNfXMX5e
         L2Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767077534; x=1767682334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VBnZJZDGhdRNGBjMDRL9eG9GcLcP9jl+sUTup0CuxvU=;
        b=btzhhLnb+5E37xt5dQYWG18wEkIXIfSsHhtcdlowfQt44salvUfz+UlB6p2M9U5+Q+
         rE9EhrhTIRvPmO5bov5koUlrIFQzmAEPncd8aCfin+JMJg7pk0s1ydyWZag7E+7f3d4n
         i9dWV9yKocak9dQfKFkvVsVvYjPWfDmcIdmgTgQu0VW5aQkrGL2U76EaZfzABXNDubpv
         YyPCb83D2E9CeqnHLw0gI1LyN4HNSC5AHVKO91jzkipco+hu7T04e/gBmltr+IktfmCe
         QbKq0lfZo+Cj1eFCzcq7rqcPXFRcc/jfsRx8tChyGwZxaGN0eCZ9ttSwIqs/m6WhnVIo
         YTpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWaKg/GYiTZ5CC+9m/s4EJAh8VuqxoNIf18pkaomHrJCJmMyKOX+zMGZdPcYN/5AaogN8mYeA==@lfdr.de
X-Gm-Message-State: AOJu0YzxgFFtKd2zLOTSieOrOh2EusgTlbYHjNHdvmFeIhMw3u6w6lgu
	GGbfJUPep02WK0Nh3xduquE7U6ojkGYd63HObNpabKofn5YQNRp+2Me8
X-Google-Smtp-Source: AGHT+IHBiMtjPg1AlYHdxnEABNatADHbRLjxhDOXxsK1wVZ2SL8596U30rUF4mKfEkvevB3FZjDM0Q==
X-Received: by 2002:a05:620a:2910:b0:8b2:f26e:3226 with SMTP id af79cd13be357-8c08f6580ccmr5147708385a.2.1767077534187;
        Mon, 29 Dec 2025 22:52:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZOUORIKsxP80T+uY2MRn3ifv7tiJNc+/s6wi6mZRfoNg=="
Received: by 2002:a05:6214:33c3:b0:88f:ca81:d5ee with SMTP id
 6a1803df08f44-88fca81d95fls129987196d6.2.-pod-prod-05-us; Mon, 29 Dec 2025
 22:52:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXjGkR9XdOUXDssrkAz9VIc+PyDI4tRTmy2I71jbYj+FgvdSxzf1uJKnEmNUFfSpsRCl75In3i+4iI=@googlegroups.com
X-Received: by 2002:ad4:5ce8:0:b0:890:1b3:e3f3 with SMTP id 6a1803df08f44-89001b3e5fdmr190565336d6.51.1767077533252;
        Mon, 29 Dec 2025 22:52:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767077533; cv=none;
        d=google.com; s=arc-20240605;
        b=JIPFp/Sj+C3Saf2snMEFTz1TlT1LdRbBScnwMIDg2Ls5KZp8OwBh+1l5gR+6i8utDP
         vgC9Dx6/4I6PHGA+IA8NX/0JW/yle8jRAOGQ1HvYcCXYXRk6rWixvpebiXcu4ZwOubHk
         ZlXIY6bEyTL122bKjjN3qAGWV2AqVmsco3aPRpjcIqjV/32LuzEpq6l6BpZlQCyHShUP
         NpAR8/OImx+RWBPK+xexKteXatBt6BQ1qWmm2URDRWm9ZsH5rs+CJM3UmQu3SZbM5ITL
         YNyNxz6yPP5WDbVnzAh+NLfOBmm9ftjxllpl9jxiQDA6ayYlhwOmA9Ywx39bU71+1ggi
         Mpeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=6U9rLwZNIYS9DVA5ViRqLHmiyAVD8oKnKmSgx7+9CoU=;
        fh=0nm2cq1/q5wqqq6tA2DvE1Ei9//TSEErLckiLxKr8AU=;
        b=GzzS7Tuwzrc6mUXTESQkGQDKifreelQ1yuZ39wPyCaKWCdl1SigMovboR4KibGdUn9
         Jc3cOxakjMovYfhao7hrjO2NthIAgPmE+6992cs6znyUNLYMALCE2keWF+9J9pqzsMPZ
         YRrhhjmMBe0ftATk0CBJj3LkgVaxgXJDHaAtkO/a/2ZlguN6GLhsMYe+6eIp2YW3yA5E
         IiYSuMEzZi1cf4R9Czh7to81/ZGLizk1uMKP3flRs8ChKRsjQx9nlLLikRL4YQqFyq2T
         woRpM3dpv15VyMeHP/olviZ8I1mZwYk/Bc8fA+Vs2cy5deL4VJvxRmM2mIxFzHHRVXPK
         DaWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JmO9eH9o;
       spf=pass (google.com: domain of eddyz87@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=eddyz87@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88d971b69a2si14893166d6.6.2025.12.29.22.52.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Dec 2025 22:52:13 -0800 (PST)
Received-SPF: pass (google.com: domain of eddyz87@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-2a0d67f1877so123963415ad.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Dec 2025 22:52:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXFFtGS/0VUTy8BhTm/CKgZwinWJrFgVq5CWIb1b70CbLm9/MS1C++50uzoH7+X9OLKh90o4QoTvK4=@googlegroups.com
X-Gm-Gg: AY/fxX64WQjiloiiDoQYZiMP7We1h895O5kfTIMy3f7Fz1a0BgvdoflVBCKsx6z6BSm
	Nd1dQjr53An9i4ysjRbP4Tx2o9FNRpYc1vbU1akRxuR2CyrLgLGK1tGWCoWyXMOaVuIWg5/VIfd
	TaMluNVY5d3s256oE+OYZa4vbEqFzIKXBqLCQi+rH9x7olD53XtwZLilS66Ut6o8Jv2ToVM0ILq
	keSjJS1wP69wH1jxyE/s0xu7MADzWcvQaghdhrfIxi8YDDEx3Jp8V5c0nefnQR9y7fwHJG14JIJ
	qfycEqKeZ71fE2azaaaumoW8XBGfabrrmzeudvot/8OKbTXJ/NRD7jxQu509HWBwBeRGM7FRzR3
	mg+Z7O/7EKCQ00fmRFZuRnlSUctXbC7efeg/enYHPziATOv07bIoZH9x5faLSVoUjuLdSkvJ4KY
	1L3v8FwnXM
X-Received: by 2002:a17:903:41cd:b0:298:55c8:eb8d with SMTP id d9443c01a7336-2a2f272bd8fmr294469855ad.35.1767077532151;
        Mon, 29 Dec 2025 22:52:12 -0800 (PST)
Received: from [192.168.0.226] ([38.34.87.7])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a2f3d5d20dsm291184545ad.67.2025.12.29.22.52.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Dec 2025 22:52:11 -0800 (PST)
Message-ID: <e3c26c7c9a74240b1fad2237ea0b4e205f3c1f0d.camel@gmail.com>
Subject: Re: [QUESTION] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
From: Eduard Zingerman <eddyz87@gmail.com>
To: Jeongho Choi <jh1012.choi@samsung.com>, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Cc: joonki.min@samsung.com, hajun.sung@samsung.com
Date: Mon, 29 Dec 2025 22:52:08 -0800
In-Reply-To: <20251229110431.GA2243991@tiffany>
References: <CGME20251229105858epcas2p26c433715e7955d20072e72964e83c3e7@epcas2p2.samsung.com>
	 <20251229110431.GA2243991@tiffany>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-Original-Sender: eddyz87@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JmO9eH9o;       spf=pass
 (google.com: domain of eddyz87@gmail.com designates 2607:f8b0:4864:20::62d as
 permitted sender) smtp.mailfrom=eddyz87@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 2025-12-29 at 20:05 +0900, Jeongho Choi wrote:
> Hello
> I'm jeongho Choi from samsung System LSI.
> I'm developing kernel BSP for exynos SoC.
> 
> I'm asking a question because I've recently been experiencing 
> issues after enable SW KASAN in Android17 kernel 6.18 environment.

Hi Jeongho,

I'd like to reproduce this locally, is this particular kernel version
open source? Could you please post a link to git repository and a
commit hash you see the error at?
Is the BPF program being loaded open source?

(Also, could you please post the output of
 scripts/decode_stacktrace.sh for the stack trace you attached?).

> Context:
>  - Kernel version: v6.18
>  - Architecture: ARM64
> 
> Question:
> When SW tag KASAN is enabled, we got kernel crash from bpf/verifier.
> I found that it occurred only from 6.18, not 6.12 LTS we're working on.

I don't think that commit "bpf: use realloc in bpf_patch_insn_data"
had been backported to 6.12, it is a performance optimization,
not a security fix.

Thanks,
Eduard

> After some tests, I found that the device is booted when 2 commits are reverted.
> 
> bpf: potential double-free of env->insn_aux_data
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b13448dd64e27752fad252cec7da1a50ab9f0b6f
> 
> bpf: use realloc in bpf_patch_insn_data
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=77620d1267392b1a34bfc437d2adea3006f95865
> 
> ==================================================================
> [   79.419177] [4:     netbpfload:  825] BUG: KASAN: invalid-access in bpf_patch_insn_data+0x22c/0x2f0
> [   79.419415] [4:     netbpfload:  825] Write of size 27896 at addr 25ffffc08e6314d0 by task netbpfload/825
> [   79.419984] [4:     netbpfload:  825] Pointer tag: [25], memory tag: [fa]
> [   79.425193] [4:     netbpfload:  825] 
> [   79.427365] [4:     netbpfload:  825] CPU: 4 UID: 0 PID: 825 Comm: netbpfload Tainted: G           OE       6.18.0-rc6-android17-0-gd28deb424356-4k #1 PREEMPT  92293e52a7788dc6ec1b9dff6625aaee925f3475
> [   79.427374] [4:     netbpfload:  825] Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE
> [   79.427378] [4:     netbpfload:  825] Hardware name: Samsung ERD9965 board based on S5E9965 (DT)
> [   79.427382] [4:     netbpfload:  825] Call trace:
> [   79.427385] [4:     netbpfload:  825]  show_stack+0x18/0x28 (C)
> [   79.427394] [4:     netbpfload:  825]  __dump_stack+0x28/0x3c
> [   79.427401] [4:     netbpfload:  825]  dump_stack_lvl+0x7c/0xa8
> [   79.427407] [4:     netbpfload:  825]  print_address_description+0x7c/0x20c
> [   79.427414] [4:     netbpfload:  825]  print_report+0x70/0x8c
> [   79.427421] [4:     netbpfload:  825]  kasan_report+0xb4/0x114
> [   79.427427] [4:     netbpfload:  825]  kasan_check_range+0x94/0xa0
> [   79.427432] [4:     netbpfload:  825]  __asan_memmove+0x54/0x88
> [   79.427437] [4:     netbpfload:  825]  bpf_patch_insn_data+0x22c/0x2f0
> [   79.427442] [4:     netbpfload:  825]  bpf_check+0x2b44/0x8c34
> [   79.427449] [4:     netbpfload:  825]  bpf_prog_load+0x8dc/0x990
> [   79.427453] [4:     netbpfload:  825]  __sys_bpf+0x300/0x4c8
> [   79.427458] [4:     netbpfload:  825]  __arm64_sys_bpf+0x48/0x64
> [   79.427465] [4:     netbpfload:  825]  invoke_syscall+0x6c/0x13c
> [   79.427471] [4:     netbpfload:  825]  el0_svc_common+0xf8/0x138
> [   79.427478] [4:     netbpfload:  825]  do_el0_svc+0x30/0x40
> [   79.427484] [4:     netbpfload:  825]  el0_svc+0x38/0x8c
> [   79.427491] [4:     netbpfload:  825]  el0t_64_sync_handler+0x68/0xdc
> [   79.427497] [4:     netbpfload:  825]  el0t_64_sync+0x1b8/0x1bc
> [   79.427502] [4:     netbpfload:  825] 
> [   79.545586] [4:     netbpfload:  825] The buggy address belongs to a 8-page vmalloc region starting at 0x25ffffc08e631000 allocated at bpf_patch_insn_data+0x8c/0x2f0
> [   79.558777] [4:     netbpfload:  825] The buggy address belongs to the physical page:
> [   79.565029] [4:     netbpfload:  825] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x8b308b
> [   79.573710] [4:     netbpfload:  825] memcg:c6ffff882d1d6402
> [   79.577791] [4:     netbpfload:  825] flags: 0x6f80000000000000(zone=1|kasantag=0xbe)
> [   79.584042] [4:     netbpfload:  825] raw: 6f80000000000000 0000000000000000 dead000000000122 0000000000000000
> [   79.592460] [4:     netbpfload:  825] raw: 0000000000000000 0000000000000000 00000001ffffffff c6ffff882d1d6402
> [   79.600877] [4:     netbpfload:  825] page dumped because: kasan: bad access detected
> [   79.607126] [4:     netbpfload:  825] 
> [   79.609296] [4:     netbpfload:  825] Memory state around the buggy address:
> [   79.614766] [4:     netbpfload:  825]  ffffffc08e637f00: 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25
> [   79.622665] [4:     netbpfload:  825]  ffffffc08e638000: 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25
> [   79.630562] [4:     netbpfload:  825] >ffffffc08e638100: 25 25 25 25 25 25 25 fa fa fa fa fa fa fe fe fe
> [   79.638463] [4:     netbpfload:  825]                                         ^
> [   79.644190] [4:     netbpfload:  825]  ffffffc08e638200: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> [   79.652089] [4:     netbpfload:  825]  ffffffc08e638300: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> [   79.659987] [4:     netbpfload:  825] ==================================================================
> 
> I have a question about the above phenomenon.
> Thanks,
> Jeongho Choi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e3c26c7c9a74240b1fad2237ea0b4e205f3c1f0d.camel%40gmail.com.
