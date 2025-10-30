Return-Path: <kasan-dev+bncBAABBNPQRPEAMGQE3BT5PAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DDB2C1E6BD
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 06:31:35 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-4283bf540cesf302534f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 22:31:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761802295; cv=pass;
        d=google.com; s=arc-20240605;
        b=COcScQllbDdYqdF3pc/RxeizqG7ovT8izd0Ixzl87r0H3oAWr3hsQiYrLgGWIeETlc
         uwWyOEXYvbN5qaf/H4K0JKmCdu8WbDzDpzZgjLdiM0SZ0azDDYgCDbYpqjZrd0YEu2Sk
         G61OD8lxT23b4StOa6w8sFh8QjI7AZg9h80OZcsUJaUUO7rVRBWe4FbPlzHmZ+uVe+Mx
         dbtdaTwCNUZ1wu64U+8AsK7IkgwEmCP+JUOMOEtX1ZM0Fr+l0UiirF2R3E5/1obKNHlW
         3tW3tEuMMv4fkeMYQRs9SIzLvbgpdxLE/EK+4MaZcHoy2JXtLpYaEypy6z7qBOnSwnVB
         uY7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=bRgF85XwHanWLHCknu9EzSPxbnGjS4ZGkDz0HMmJ3B4=;
        fh=srz/DCYss9SUBhJKxLfpCICjNkANIfFSOqpOtWrlmMM=;
        b=de8ZtjRbfX931OYUdqMAw/iSPRhqqVNq30l9GEJGd9ZUGvLclN/YPMAvYLhFUyQ4kH
         RMZrSWjcKMayLU5JpN8IbQWk9si3daWVQKbZ0AYWuRNlU8YbpNo6jJi0A4NFGbjtRQsk
         b/lzUGUuhovUAUuwXLRlnRtrgrsSfOW6oC5kfA2U0z2pGvsV/VKD/urFuR5cU+S15+v5
         bi4YnBAyf+HeloZ+Q7TIx8Jr+x9tnIY+d20O4XoTGvWaLG4V+miFtE2KTNYHuWsh/EZV
         VduopjdaGCoX649NVDSy0WGD2G1RTv9vHXSClJIcQ/LwhrAex6tlPVDF5PdgLxEH6vwH
         xFIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Dmkbwjuj;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761802295; x=1762407095; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bRgF85XwHanWLHCknu9EzSPxbnGjS4ZGkDz0HMmJ3B4=;
        b=uIlfXsUuRzKAHqT+ne0v8D3DOtylLJtYBXdHZFEWhCBDkfwDoqujItlElG13bg2cQO
         7wXhnOUn9pAhWyWdHVpI+NVnLloqWMGOqzSeIuYCqHnfXUxn27ljumW+JcbDtDZsKJE3
         4pcHUORfK1Fhf8i+9GMTPZhLVq5jj4WM5sivxNan/1zhtq7o2+cTYJNInUZZSMB8uFwg
         KuXNJvjXLntWUuDCOtfmZTYtH7TlYNzd4e19qh2mfAW5cRO31yUNW8nfd6nbRTOk6McB
         PnCt4zWGyj7jMfuxLi2meTq5oxTSgnhxZD4reQLzSWqvv22CsXm5TQbAYkFJ4/PRn84b
         W2Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761802295; x=1762407095;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bRgF85XwHanWLHCknu9EzSPxbnGjS4ZGkDz0HMmJ3B4=;
        b=GwznrFAfypaxzYvB3h/gMDoe5DfnHsM6ywwoVNBEYh8CBbPW4x9euf3fIlqUgBSJeA
         8E/+XqBhlDWwWwDiTt9Sdosj8AKW6tov8qSdjyQMdUrvOU3TnASJY1aynGb37ctlbdiy
         hLhRnTL3hYpA/vp+rGaQLtGZ3tN3vaR6nj66a0nollMK6Ilj2gKjqPrWWvaqXp1xr9my
         7djRfQttkgWzucGm/77NlguecFh55R389e5R+ehAEpDJjrxscwJnt9ze7NhKWmtt28mf
         1QTDomXxEzu8tEt7acWy+GWPUftCIOnLjnZpVyQfzZHH4b2G8QnpA48AP+JWvJ1VoMUR
         1bZQ==
X-Forwarded-Encrypted: i=2; AJvYcCUahGbqU32Bal/pzzmvuK4A8pdNJQJogzza4m4HfsATlD7+GmHn7KujW/Nz00wryYz0ZDm71w==@lfdr.de
X-Gm-Message-State: AOJu0YwCHqaJA0+LG1rTb88jv5W6QwuJUzIQ2Lq8B0J8WzdTC3KO0bVU
	VRtthnUs4UJakFb9CWLz4deiSOaSaxiH2fokvGXTWnnkceyEPqCh5HRX
X-Google-Smtp-Source: AGHT+IFGMXj7HLS5SoeX9Jc5dqSxd+lJdJN8yIY6JQFdBkE+BLtlUcDdAs5WB8oJTASyNfFZqiuJgQ==
X-Received: by 2002:a05:6000:2282:b0:427:8c85:a4b0 with SMTP id ffacd0b85a97d-429aefcd9ecmr3877289f8f.56.1761802294468;
        Wed, 29 Oct 2025 22:31:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+awdV8o3GTWQf3EaVXrXqp6ptX45ZxQql/WNjh4QnlSBg=="
Received: by 2002:a05:600c:5491:b0:471:a42:614c with SMTP id
 5b1f17b1804b1-477279c1d41ls2291935e9.1.-pod-prod-01-eu; Wed, 29 Oct 2025
 22:31:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVkeoWgizTLL2CrBWO7uQIAF9iCjBs3rPmhkOnKWrqRQDvFW1e58JPZpU1zYUAUsq+e311XmSq/hFA=@googlegroups.com
X-Received: by 2002:a05:600c:c48e:b0:477:942:7515 with SMTP id 5b1f17b1804b1-4771e17e177mr42717845e9.11.1761802292274;
        Wed, 29 Oct 2025 22:31:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761802292; cv=none;
        d=google.com; s=arc-20240605;
        b=FuHcuapqND2S4Pd8PNV8dxWdtmMH4yAalfpeS/OR8mmzFhYndxrILjwn2dPnc1YTPi
         JXbdJeTGaQxLS8FRq7YgTmtHZwBHsMiN0oFfTmHFuXujw1KKRU9dBM352LUFv5910Trd
         HPWXbI3aFHI77QFXCCy9oUFGVpDt0ZVXCxXCnt345oORxNINCY+kM6HbtT67moWbN9nE
         KI0JZrS7igA/ARBOb3UIUeG7XhiK1I60ZHyqMgLSWEkMcItkTohpinQvj50HFYae60gJ
         GgLUO27TcMk16JMrdvy7MoyPryh8ZIfzxG4+49zyvgrum9RFF15MWZlFCnupz1a9mzfu
         71tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=SqB029SpVmJqfLswaEolkge/L1HE0Gdq54LxorgJlpY=;
        fh=SnF/VXhqiNnSsDXMtPo98ZMU4ZEe64ououyKVELhZrw=;
        b=Ij/EYk+1+7Id5XUrKw0W2JU2YRuSbKwthrrFaFdmppfQYMAxz28hdivW9hd8DH7o4n
         u2sv5dKxoSzMwLJzY1Mdwzx3WexrSkUCMmOT1T4p+ET70a2nTj75iTeSDEK6Rww0kj24
         nM9iPSrjKj4Q2tnEd+Z1gDOP1vijJCpVkPSC9zcX0+ZlvfrlOMzJX7qwJbynlTCjRQGr
         W7Kg3x4PyeLhl+vYVyN4hQhcgxaIuFDuRx4hnuagZWf329ApNo6UBBzRhZH0Q9HH6tmG
         hcf0un8X/1kMMucW1BLPUuCzjghm3Wm3BabqUZBVdVTyZXOxLs3UaWCkfOmVjwfFv+NQ
         tH/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Dmkbwjuj;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47718d6148asi771075e9.1.2025.10.29.22.31.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 22:31:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Thu, 30 Oct 2025 05:31:22 +0000
To: Andrew Morton <akpm@linux-foundation.org>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org, Liam.Howlett@oracle.com,
	nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 00/18] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <ngwfbor66uhrgfe2g4nvziwqp3gtsbndlpnhnov7ew7535dysv@ieypsfjfmnlo>
In-Reply-To: <20251029150806.e001a669d9dad6ff9167c1f0@linux-foundation.org>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <20251029150806.e001a669d9dad6ff9167c1f0@linux-foundation.org>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 22e7e1e747884a326f20da03a155c805b55537aa
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Dmkbwjuj;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

Thanks for taking a look at the series!

On 2025-10-29 at 15:08:06 -0700, Andrew Morton wrote:
>On Wed, 29 Oct 2025 19:05:27 +0000 Maciej Wieczor-Retman <m.wieczorretman@=
pm.me> wrote:
>
>> The patchset aims to add a KASAN tag-based mode for the x86 architecture
>> with the help of the new CPU feature called Linear Address Masking
>> (LAM). Main improvement introduced by the series is 2x lower memory
>> usage compared to KASAN's generic mode, the only currently available
>> mode on x86. The tag based mode may also find errors that the generic
>> mode couldn't because of differences in how these modes operate.
>
>Thanks.  Quite a lot of these patches aren't showing signs of review at
>this time, so I'll skip v6 for now.
>
>However patches 1&2 are fixes that have cc:stable.  It's best to
>separate these out from the overall add-a-feature series please - their
>path-to-mainline will be quite different.

Okay, I'll send them separately

>I grabbed just those two patches for some testing, however their
>changelogging isn't fully appropriate.  Can I ask that you resend these
>as a two-patch series after updating the changelogs to clearly describe
>the userspace-visible effects of the flaws which the patches fix?
>
>This is to help -stable maintainers understand why we're proposing the
>backports and it is to help people to predict whether these fixes might
>address an issue which they or their customers are experiencing.

Sure, I'll also fixup that undefined symbol error that you mentioned in
the second email.

kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/n=
gwfbor66uhrgfe2g4nvziwqp3gtsbndlpnhnov7ew7535dysv%40ieypsfjfmnlo.
