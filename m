Return-Path: <kasan-dev+bncBDW2JDUY5AORBSHU7TCQMGQEJZEOFAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A452B49ADE
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 22:19:22 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5607b2fa3e2sf501765e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 13:19:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757362761; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZZ4hRFLCNolzQMk2n46861I+B5lDr4e5Cu0k2eC9KY7jMA90AJsCm+InAzC8zicgSN
         onDbLqwpKs/hKerpx9lZnpblSVdN5rAF2hdTccnnulssUd/6y5aXOLGkXmuwSnM4cf6N
         M8ZFsn2iUDmLxU3cqcH507qFqpYYQyiNDnfLkHUCLPdZm6kEgKLOxioqev9/fYmvu14L
         wW0eNpRIQI0Ona5z4/XGXB57LL/BGL2O8aW20u2XS+VdTZrP7iqgaXQ6V9vIeSwhKyyN
         CAypBLeySbrEp/0W3enb5DXQ2ZKz7bPgYc5kAWO6FPCbjLVuOzvD6yxC6UBPPMiTQ6PR
         gdsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=h2uSVMJY98kt7fK1L1LF3+zqrspT+E/SWP6soBg0b/E=;
        fh=3KywYl5sK6EFuiYNbv4OIbWsgKTZwlaRqoZt32jM8YA=;
        b=H9Nbmro/Iuo7xxvjU0nd3Doh8Q+u/kouieQuo+XXbCjrPT6hn331gqeY7O2DxH9yZB
         3KSlE4VcP2TIFjr6TturlGxZm0/3qbZeMiSoQRRQG5o6MziNTgF83FCmyrC0t5awcTSv
         +b2x6CTCI5tcSgCWY+eJuQ/M3qS3fbwtzybS6yx4wrqtuyeK4D0MLC1QRKgHfy1cbDUR
         ToZIamVlkAB7W1qGbnQcBT9O7jaErmqG7j+jSjDTKc3Ga/5P2Leu0A+soTdOI1nZZ7ti
         6zJMoOb/ADPH9v0QOc7pnDWvW/KQuvWDRSMGbbnuZqNYCWsFFkWtVNZenri7KzNPGX2P
         O2PQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ggv5/A2l";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757362761; x=1757967561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=h2uSVMJY98kt7fK1L1LF3+zqrspT+E/SWP6soBg0b/E=;
        b=H9+EONKPk+CTyp//O7/eIk+6e9K74Ed58n5qUPwJ3j9xlmu4Qmjq1lnr94lr+OawXl
         wdFDlltwfpPvtpnBJcCG8sUHDDQVXsdezXXXTYVTR4cEtlKlLG4YTlN3kXiomyUtHYiv
         hwBmvoWmpIsxDLdJzFMjQ5OJ0cGcyP955WLut0s40AkfNg3302GEq+iIO8rxMucXL90j
         k13Qjoc56rNB6Z4ULcT3y5/QCN3pnzjQqYCgrCW1iSRyNZNwt2cE47OgOfBg2QCxmmMG
         Kke6U82H20+GHPlbfx7RyvoZUHdA8RMyV8ZgH5rSlXJOq+6/AFkhzwBD2TtCnadlBX/w
         IfIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757362761; x=1757967561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=h2uSVMJY98kt7fK1L1LF3+zqrspT+E/SWP6soBg0b/E=;
        b=JexhbAfm2YvnHOZyvSaNmu1iqfv5xho0CG9n8IHYsIMMPOfDxHt7jt8EDcnm6foEf9
         Cyf7ZOHk9KQPNfdezZ3Xbcl1u5aWEpGWsrwsX5tTOrJZWAUg4A287Sx2obUsM4fYVDdt
         ZtJ0n100lsp3lFpMYUVfnNoTdfC/RgKkU+/hFMukcIOQ2tQOHEvPS9skOZ4ykvsQmKQE
         NhFgHBtZ6XqkUAVaCyA99QGXGtNn/RZXUoBrtSw8Mu3lYmlclVgcYBk6muZ4ZLsB4OiJ
         h28+lFZSjgicms9OUmbdp7+YF1CJSePAVmTQFxN279TWZhXsvm3urCiJISFMLjCJQjVB
         WUbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757362761; x=1757967561;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=h2uSVMJY98kt7fK1L1LF3+zqrspT+E/SWP6soBg0b/E=;
        b=C3JQKJYLCfYxHKgEggM11rboqxoXKow2roL9LgH7npE49TKoiPIbuD2HKBmE97Wm3p
         BH45IOmmR6YvRgq0B0NrWZfA6SoFmOmsHfHQfnNK7ih0Y8ZLmSQDUM88MBfnBGguebuV
         4EiUotBOYXHpdMeZqgI9+mWll8alvsCvX3QQ1Jbnb21M4dq6hNhqJ6bztc34YNah15Z4
         xRhwN/q9HqA3g/9z3zT6r89eOjH6bKSxnn92ThjtDSZ2QQV+hXJxuc2Ei2+UDv55l+6o
         dZIITXbhj12vFd9fwxIS9PmLouseTIYA1Lj9JrkCn3BeJCK+p6AazSfoyZg46r8ZF4m1
         JTCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0JKAICIX2fkwOWBlGyCQ8Bilxrt95PB+IaOxcWToeCiLTtq+I+c2Dww2wjc9dAKEVTQ7hGg==@lfdr.de
X-Gm-Message-State: AOJu0YwXX0g4ifwmjRgXx/+kmBlsWTHjwfoUACZtEG1zUqYZtNKhE+eQ
	OwL8MarhVrZ6DDLUM1RZ5XtB8VEqkKihMFCd1k8PXnjhH9KMyIP1KHxE
X-Google-Smtp-Source: AGHT+IG24bHkwvl5YQiEfxUsMPKLPnLps+tDr4nUz/GaU1Uk6n5gcoodRjZoxKd+sVtOOHZBY0Fggw==
X-Received: by 2002:a05:6512:3989:b0:55f:3917:1df3 with SMTP id 2adb3069b0e04-5625d0a3d6fmr1451167e87.0.1757362760864;
        Mon, 08 Sep 2025 13:19:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcwOS8XmPTGqGg5I57KqO1C6c4ea80btb41t9R37eaKYA==
Received: by 2002:a05:6512:22c4:b0:55f:48d5:149f with SMTP id
 2adb3069b0e04-561663d39c3ls711835e87.2.-pod-prod-01-eu; Mon, 08 Sep 2025
 13:19:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1JCPdPuKckFb+2RgQRX3smmpb4LPSqbkw0hyaeE+1Vf7elXhBfB2ALpeKBi2sRbp7Gsv8f4GVNkA=@googlegroups.com
X-Received: by 2002:a05:6512:3d27:b0:55f:4efe:42d0 with SMTP id 2adb3069b0e04-56264167ac9mr2321608e87.41.1757362757951;
        Mon, 08 Sep 2025 13:19:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757362757; cv=none;
        d=google.com; s=arc-20240605;
        b=N8fOqFRjTxEy3PleCyGyJstK9Qbg3Yn2ltx9RMygEuoIpl6QvBdjIeAYLH+nlgq9ma
         cI7UyjUsazO//4LZwv8m6Owdft9HZki6pHG1WxaJ8pePZlo6XV91m4HtPjSu3icnA27W
         lfXshUPVMpSlWh5tt87SAROT9yR9yE5cBQO6zbVhMleH80Aetbt6xc8R8y5dLzX9uinZ
         NVdnfJoSKR2/nZpPGepWui2TW+w/THKsJDJJUiAW0Mvc23tusD7tqNlBp+iabcccdW67
         FoWFvQKtlduMbHtzMbr9VGEhl+HjJVM2INZbzejqB+cUhs2q3MZaDP9ZF/Eh4KV0SJEM
         FlKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vT09vTia8SgQBO+FiegSxuy3xNGmzzHUSLwcepL1OEI=;
        fh=p8Jo7HTD2/E0nC3cGsX12UAdKeEQk+VMVyLjOThLfco=;
        b=aQ7v60YU2fYjXiVvzmpF6469rUFKpLVWnJNHbyTmXMGr5E4zXCq7jihMluawIsD3ZH
         o0TgSeOkoxpO+axrrP84LwvQjjH/rxmhhq0W4N9gY3XywwUgizsa+iBtpzmE90WctC0N
         B6Y6pLZgN0Sz6AY+tjkLeedSCJxifKGCmI4JDDhRIQt2Sh//xwPcgCRLO6fbCaP99rp0
         FTnXeCMbQ8naSJBC3SmD2q+CrDXbKcXkMt4Yi7uHkfwcLPP5ZO5sN88Lr+DFWXS7uEGO
         tg4ZL2E+OA5hLZqnVZGIqTwhXJeOzETxPmp1yqpJwQGXdBmXxJ0Bo8ZEWkyHqLNq4bY3
         4wBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ggv5/A2l";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-56369a99766si124201e87.7.2025.09.08.13.19.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 13:19:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3e34dbc38easo1994804f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 13:19:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW8nPgAgH6ysVJm/hIiTqgJJlv9D0qvr9tqXzFPD+knJQIVdltKFqfQWhct8ExxWbbk+V4g3/oh1YU=@googlegroups.com
X-Gm-Gg: ASbGncuSNeDKfQTz8zLVssP/d7zyohJ3lH4OzK22h++/0m/R48ZK0JvTlJOVrNnQ6cx
	EYyYMOc1aLHFpUL0hXGjituFqoy0hulcAxEbt0S++FCt1hulBbDJdicwYpaI8xz0dRjepyhTS2e
	PGxNu0YZ6rrmRn47+/CMcEn0PwjPW48CX73UYwryeJNPLjzbxgzGgP2E2D90HIKcYh/mTmDG7u4
	VYQqvzY
X-Received: by 2002:a05:6000:2f86:b0:3d2:6129:5505 with SMTP id
 ffacd0b85a97d-3e64bde66c0mr9404161f8f.36.1757362756927; Mon, 08 Sep 2025
 13:19:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n> <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
In-Reply-To: <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 8 Sep 2025 22:19:05 +0200
X-Gm-Features: AS18NWBlgrNec5HQDqXuFdTg0l1auT_Opy5K148gspXva4oeYyeCVxabENuTdwg
Message-ID: <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="ggv5/A2l";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 8, 2025 at 3:09=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >>I recall there were some corner cases where this code path got called i=
n outline
> >>mode, didn't have a mismatch but still died due to the die() below. But=
 I'll
> >>recheck and either apply what you wrote above or get add a better expla=
nation
> >>to the patch message.
> >
> >Okay, so the int3_selftest_ip() is causing a problem in outline mode.
> >
> >I tried disabling kasan with kasan_disable_current() but thinking of it =
now it
> >won't work because int3 handler will still be called and die() will happ=
en.
>
> Sorry, I meant to write that kasan_disable_current() works together with
> if(!kasan_report()). Because without checking kasan_report()' return
> value, if kasan is disabled through kasan_disable_current() it will have =
no
> effect in both inline mode, and if int3 is called in outline mode - the
> kasan_inline_handler will lead to die().

So do I understand correctly, that we have no way to distinguish
whether the int3 was inserted by the KASAN instrumentation or natively
called (like in int3_selftest_ip())?

If so, I think that we need to fix/change the compiler first so that
we can distinguish these cases. And only then introduce
kasan_inline_handler(). (Without kasan_inline_handler(), the outline
instrumentation would then just work, right?)

If we can distinguish them, then we should only call
kasan_inline_handler() for the KASAN-inserted int3's. This is what we
do on arm64 (via brk and KASAN_BRK_IMM). And then int3_selftest_ip()
should not be affected.

> >
> >What did you mean by "return the same value regardless of kasan_report()=
"? Then
> >it will never reach the kasan_inline_recover() which I assume is needed =
for
> >inline mode (once recover will work).

I meant that with the recovery always enabled, it should not matter
whether the report is suppressed (kasan_report() returns false) or
printed (returns true). We should always skip over the int3
instruction and continue the execution.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o%2BmY4MXt0CYhcQ%40mail.gmail.com.
