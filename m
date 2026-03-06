Return-Path: <kasan-dev+bncBDP53XW3ZQCBBHMNVTGQMGQEHELT5XY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sHzUNaAGq2kMZgEAu9opvQ
	(envelope-from <kasan-dev+bncBDP53XW3ZQCBBHMNVTGQMGQEHELT5XY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 17:53:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C3D922583C
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 17:53:52 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-35842aa350fsf40727480a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 08:53:52 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772816030; cv=pass;
        d=google.com; s=arc-20240605;
        b=YP0ZR1gyqrX8RiJ/QEuCc87WQtHB36RCE79zUUJQxBOEN1C4uUh+AjsydX4+0BpAUG
         B+qAKNIfAxBPxPGRwi9FMS45hROy419AWd1K+0zFuq1M6CeASZeK7M85CZsBsWdcKxeJ
         kvMC5pfgmVg77wJz7Pv7VlA1JFBrhv9nZo+ceiBaf5uXp2WN//M2A7nqADY/3fHuqkLB
         VgnCzAcqAPIhKyMKoLHVkX9QvwWYKyI3DDbmwJ6bqb1vEqWflS3nCo46xS1wijqG6Y7j
         oJQTN5qvLhuOkUUbnxEkCveU3NTnSv9sS4WAvB5OQnxBlo4e49fRnPVt8B83BKSFRppl
         8UEg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CI+nMZr8Oo04VHIwm/JWt4vf/Ft9BnPw3/6uGu6KZ24=;
        fh=6M363m4seAZF3XXvkKt5kVkD/6/9IAMyMNP6pHDgPC0=;
        b=KSBo9sbn2L9t+/vvh31AxQGiA6LixjOcYaJIlIxoIIOoao2AM/evYJul/DhAnSvMpe
         Xa4dTDoBG7xPskqLLgbr2JbtcOSbmLqRUmZsaESwebIyw5K8dUA1X6lmgOkkGlEvMQ7s
         9gs6D0U2hbZGhRwChN4LvEPQHsPe5Pvnubgwbj9bIWdlTpiAy5+t+2528N4m+8SmGzBS
         v3tFBBqW8uuDgPk8WyKYtKh+RBrKnahPQQ+rc3ltfWgvfl/pBiyLJU5B/Vf0Mx/LpaMI
         bLRNs/hmQY0DGoDihfAIB2F6f1Or+5nHfV47vIpqrjGX/WtsB8jBRSR+huS2OwricC53
         GRrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eEZoeIeU;
       arc=pass (i=1);
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1232 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772816030; x=1773420830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CI+nMZr8Oo04VHIwm/JWt4vf/Ft9BnPw3/6uGu6KZ24=;
        b=C231fRBLzUohl2iEuxFLnQDhaJJIhGJUnDIos8vyFOs4igbQQ4mnedrD2FueqtobPF
         ANhJOBgvkzCWD5qMW4pYbXGDecZ2qNdrU8+pp1uMOsbQ36fJlPP981BwtuSLgr6aepNt
         2ynppI5iraZF6fd4xxIN3hGA+9EZobw6+DMdq+gP3V1ojvztqbq4c4oEqm4JXjdL6xdz
         WdnK9Xn912pN/lvpZF8kWi2VDy7tCZhsx5PCUElCAUhadfKnzm/6TWf2pBRvh+dFXKpm
         MfV2ybMUKG9SWFJLaOsOKJ2ckAeQ7Hj1s9h5t4n5SxFAKbZCGjYh+3hAH6LO0rHsmR0E
         BRDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772816030; x=1773420830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CI+nMZr8Oo04VHIwm/JWt4vf/Ft9BnPw3/6uGu6KZ24=;
        b=ls8EgNbqx3z0zhXbs479nn4hqRpRYAiB2f+LSmR9ES53gjZA3AEI++7ejsB9LVflDK
         m8WqxrI6Qd/sxWES2MSthuflxR5Q7DGzJAEiMzSy4qwUkmaYtCLLAvGdBNgavIlxblDN
         6wc9Udl2fNC8+n8Z8KI5wxsNdgroBMliBy3k0UHynXyCcqavTHki2ZCg28ySkEj3I0iX
         Cp4rfTfgf1MQxPxtBlf09Rm0itCxUpIOkhV8mOP4wuRZ2nPJTRFuZnSk8SPOlyuPlw5m
         q5i/92PgbeCsEnv+EApX/IyqihRgFLCXS2jRxRRZu43MpksqoC+XDcSmhDgBehDDbdhz
         KaVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772816030; x=1773420830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CI+nMZr8Oo04VHIwm/JWt4vf/Ft9BnPw3/6uGu6KZ24=;
        b=rQYSWL5kcH9eHTwSuPC9gKY834xpjMnui8poTuKLo4eQtc5ennaWCmgTuw6SBxkG4Z
         KPgHwFz9OsS3RCqUQmt8vgrgCLa0YM5mkoAus/p4iVZ0b4M+lNpDqUiKfl0atoZLjJxD
         HIa4FedOnXQMnj1HmMnFVGaKc7aqJ+618tm0v5wS+G81QO4AVxGJsRDkwLpGbL9R4Vrc
         iysrYjPc1Ol6qiTkCb4K2iIRmO/79wItRmc84LjizLqUs5Q0gg8rb65AJMIFyRv1M/HO
         FyCiKSlbdqiHkOKdSBjkOrG8szUElYyxmo9gsf34L049GoBWobUviriBPu0rXFdiE/Pk
         VygQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWt0kDmfKddLCxPcQTDjMfjJF4NlgOogaaRmoybXtm/1L98ypFx6TWAlIxh0qmpLFoqmotsbw==@lfdr.de
X-Gm-Message-State: AOJu0Yzm9UJuIk0r5SK4aw5dg0dBEmMVpPwgh8c4ByXpwNZvzOsc5FuB
	hB1FAL3zGEat0RAe1AhY3iDED6t5UxiEvthOrRg4ifnXAl7st0n1gC1G
X-Received: by 2002:a17:90b:4ccf:b0:356:1f96:9fdd with SMTP id 98e67ed59e1d1-359be34af1bmr2501899a91.33.1772816030236;
        Fri, 06 Mar 2026 08:53:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FNLLJYqxvfTLLc27HJ5+A/vWGjPzEq6Zd6r7XLQMTe9w=="
Received: by 2002:a17:90a:d995:b0:359:8d38:10ef with SMTP id
 98e67ed59e1d1-359af898346ls1876603a91.2.-pod-prod-03-us; Fri, 06 Mar 2026
 08:53:49 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVIYannd3ouaEcv8T1d5VKIjE4W6e5v4XoTwR5VaJZlMcr+b9W2AraI0ReJpODAAS4r8N0mn0pXfnw=@googlegroups.com
X-Received: by 2002:a17:90b:4cc6:b0:340:ff7d:c26 with SMTP id 98e67ed59e1d1-359be3082b7mr2466669a91.16.1772816028755;
        Fri, 06 Mar 2026 08:53:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772816028; cv=pass;
        d=google.com; s=arc-20240605;
        b=blVHG2xUlrG3D0rfMSxy03HqfuQ4Ph3C6HNxdKpp8ZAOz3QX5AXkuLVkMcVA5QJdnJ
         ThuvxkWm9FdKSQiN1RH+64C87IdPIv7FInOXOJ8SXw+JHCr0ZP0TvXJeSnRrxcX7fLn0
         Y/qvCfn08E0NSbiwJ3p887EctCYdCubICb9ovORaQJ4rqc5ah4j+1nXr2+vdQG7Yu3PS
         mfFYEnR6XcGao/9QXtSbAkLpnHb98rBFsbiZwQVed0R+kPIo43DZC2TNxvk5QOzmvuLe
         r0V7ayNldouy7vYgdlKOXKBK8wQzSfxFfeXEpuxF+92O9FQxve318wQDojffCBhSEhMK
         fm/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=d55lq5uPJ8gGFWTrhAL2DxmhHj1adF25qQQ5iMiqqsE=;
        fh=+W8vK8mogEXi97v7uehOTlluMqK290rcD9nDRH4fdtc=;
        b=O4jhRsccTuQTeJxGN9o9prOUoioQIcFmKqMvcqcNmgCCCLPEV4BAGyymoclvwUIjvJ
         0j0hlA1n9e+l5Lcz0SsJDJPBHp2ZcB2HD+xzk0IHELX1PXkEOtID8jwn2xNFS68nyK06
         k/Gc/g39FBJf5AwGJ6D/MilNs1/kE7jFSB/POU79qNPOMNagl9tQACBWzqAkiOMG4TJl
         KaDOUtJ54HpQA9TlHbFk+sIlIK9DPCrm9Et2OvZHl+VaC7q8POEyDCJS76WuFpzBfFLi
         Y3gSMTre4MX7bl0+YSWuaXpsBDknGXgey44CZ1DBUDTOD0HQNr2wCfzHe2nf1iTo25eG
         8RWA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eEZoeIeU;
       arc=pass (i=1);
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1232 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1232.google.com (mail-dl1-x1232.google.com. [2607:f8b0:4864:20::1232])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ae83e8d29csi573745ad.3.2026.03.06.08.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2026 08:53:48 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1232 as permitted sender) client-ip=2607:f8b0:4864:20::1232;
Received: by mail-dl1-x1232.google.com with SMTP id a92af1059eb24-126ea4b77adso12219684c88.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2026 08:53:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772816028; cv=none;
        d=google.com; s=arc-20240605;
        b=WNhTsq0IGtVwpVGst2RbRgjAz5cHT6wsLbhFEBbPqKSdFPAjJ137LEM7l8z18x2oTs
         EFMYjMy8SJd+crT1MnWd986nedvb7oLs3UCwXZGz32nt1e+6K0HPKpuf/nsUFb3ePMYd
         uyoqYprWse3K/3wJbEAghZbkb3nFJEwVkmhf5Rmz5ZLVeXWHZ+1etFElBFYnaSnnSvQH
         azgrKFFplA3M51Ev/5JhEgnI0Ag26DwxeSl9z4dGbDV1yxdpfhyQ496q41nmLMVfNS8i
         8xzE6XetRJ7Jnu9gm/oLfFQMANEKHTPeJaSaRylqJphxYcBweIBxq7wDwvwqGRhsKkIY
         0yng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=d55lq5uPJ8gGFWTrhAL2DxmhHj1adF25qQQ5iMiqqsE=;
        fh=+W8vK8mogEXi97v7uehOTlluMqK290rcD9nDRH4fdtc=;
        b=a5bTDAyG0dPnTAmnVMfLYIuLQZFWibPblJl/bM4yBFUvbdKbMzP88HMVBoCuhwPyPt
         Ay2UNYsbaHRO5JT6HheCw0aTK3TGr31sjUD2SxpimFhwwvS9U7GoSK3sEGZv6R0mYTiT
         9/5/4se1khGSvpudwPxZW9ZC10H0jMBpeX8+1Le88Bt1rOFj/ozy/TCtwoL5APyiO9Bf
         MhLLhrD00ZEBUv5nlVytVyMfOoijkcPnEBmxjABqXLxViRcF26/IT51Nd2LD/w8jkkZ1
         LQCzF2v2EEXofUiwos9elmktuKJo/VQNJGLfpTIc1jV+tWS66r9yLoMe/IE7uUKBdc/D
         tkmw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCU+C2yzmOHMtNZKst2ZpaRSI6AbBGsaqO2WKO8sDWn2Cyp/pB1biShbg2KcpWhW5BsATum95INRA0Y=@googlegroups.com
X-Gm-Gg: ATEYQzzdbGJPraNUa8cNsneTUbaIpjz+aKB4VUbwGqhpw24M1rALtxSrZKC+j7pyNaX
	5B5CoMrNmeHe7NZgUbiCyY5ByKvLDqmNljUEE8kOuvwPTPH4NRDxtTetJozN7EuoTHo1DTmROnY
	JkfUmmszzXHueN3FzwcrT+8MAE7MP1j23fLNdsam8g4Z4roC67WZCNHQ8bqw7tdT5asDQ0dvohl
	5yTLlCw9nCWxbkS1p92RC6ULC0AKd2ki4ObWOyW1YITMtHY5AGFigPqPFKm8sv2/TJiCZQ+yCh8
	E558owXMDtxQwiryvGGhLIu7y20=
X-Received: by 2002:a05:7022:2381:b0:123:330b:3b5 with SMTP id
 a92af1059eb24-128c2e8cce8mr927019c88.30.1772816027931; Fri, 06 Mar 2026
 08:53:47 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-4-ethan.w.s.graham@gmail.com>
 <20260306094459.973-1-jiakaiPeanut@gmail.com> <CANgxf6yMNZ3=xm9xVhPZDuxMc__7pQk=mti-CyD1QjUOgTJLEA@mail.gmail.com>
 <CAFb8wJvmnPv96o9Kr9VAh=cL9zMr8-5eCEmmkjtgX02_Ypa4nw@mail.gmail.com>
In-Reply-To: <CAFb8wJvmnPv96o9Kr9VAh=cL9zMr8-5eCEmmkjtgX02_Ypa4nw@mail.gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Fri, 6 Mar 2026 17:53:36 +0100
X-Gm-Features: AaiRm520AP3BKAgH-rViiwWeXF81JB5TY519npbH34QQ3iWXw2jRnyHpyWWp2eg
Message-ID: <CANgxf6wjPOoYemsK9EKrFM-eSpOgSUQvZ6kX5JyDTfC5J62Ufg@mail.gmail.com>
Subject: Re: Question about "stateless or low-state functions" in KFuzzTest doc
To: Jiakai Xu <jiakaipeanut@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy.shevchenko@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, glider@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eEZoeIeU;       arc=pass
 (i=1);       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com
 designates 2607:f8b0:4864:20::1232 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
X-Rspamd-Queue-Id: 7C3D922583C
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[34];
	RCVD_COUNT_THREE(0.00)[4];
	TAGGED_FROM(0.00)[bncBDP53XW3ZQCBBHMNVTGQMGQEHELT5XY];
	FREEMAIL_TO(0.00)[gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	NEURAL_HAM(-0.00)[-0.966];
	FROM_NEQ_ENVFROM(0.00)[ethanwsgraham@gmail.com,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:dkim,googlegroups.com:email,mail-pj1-x103f.google.com:rdns,mail-pj1-x103f.google.com:helo]
X-Rspamd-Action: no action

On Fri, Mar 6, 2026 at 12:04=E2=80=AFPM Jiakai Xu <jiakaipeanut@gmail.com> =
wrote:
>
> Hi Ethan,

Hi Jiakai,

> Thanks for the detailed explanation.
>
> Would it be fair to say that KFuzzTest is not well suited for testing
> kernel functions that are heavily influenced by or have a significant
> impact on kernel state?

With the current fuzzer support (see the PR in the syzkaller repo [1])
this is a fair assessment, but with a caveat.

It really depends on how you are fuzzing. KFuzzTest itself is just the
conduit. Whether or not your fuzzer can meaningfully reproduce
bugs/crashes related to complex state is somewhat out of KFuzzTest's
hands. However as of v4 the framework only supports blob-based
fuzzing, I would advise against targeting heavily stateful functions right
now. You are welcome to experiment to see if there is a way to meaningfully
fuzz more stateful functions, but with just binary buffers as inputs, I don=
't
reckon that there will be too many candidates.

> I agree with your point that "the goal of the framework is to fuzz real
> functions with realistic inputs." One thing I've been thinking about,
> though, is how we determine what counts as "realistic" input for a given
> function. If the generated inputs that a function would never actually
> receive in practice, we'd likely end up chasing false-positive crashes
> that don't represent real bugs.

I would argue that just because an input isn't "realistic" in the current
kernel context (i.e., the current upstream code only calls into the library
after performing sanity checks and/or validation) doesn't mean that a
crash isn't problematic.

Code can and does get reused and refactored over time. If an internal
parser can cause a panic or OOB access when handed certain inputs,
it is inherently fragile. Even if that code path is shielded today, it coul=
d
be exposed by a new caller tomorrow. Our baseline assumption here is
that if a function accepts a blob as input, it should be resilient to all t=
ypes
of blobs.

However your concerns about false positives is justified, and something
that we have thought about. In previous iterations of this work, we relied
on a constraints system for encoding input semantics and performing
validation inside the fuzz harness. While we stepped back from that due
to its inherent complexity, instead favoring a more simple blob-only design=
,
adding constraints to better define "realistic" inputs is a good idea that =
may
need to be revisited in the future.

Hope this helps clarify the design philosphy!

[1] related syzkaller PR for KFuzzTest:
https://github.com/google/syzkaller/pull/6280

> Thanks,
> Jiakai
>
>
> On Fri, Mar 6, 2026 at 6:29=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gma=
il.com> wrote:
> >
> > On Fri, Mar 6, 2026 at 10:45=E2=80=AFAM Jiakai Xu <jiakaipeanut@gmail.c=
om> wrote:
> > >
> > > Hi Ethan and all,
> >
> > Hi Jiakai
> >
> > > I've been reading the KFuzzTest documentation patch (v4 3/6) with gre=
at
> > > interest. I have some questions about the scope and applicability of =
this
> > > framework that I'd like to discuss with the community.
> > >
> > > The documentation states:
> > > > It is intended for testing stateless or low-state functions that ar=
e
> > > > difficult to reach from the system call interface, such as routines
> > > > involved in file format parsing or complex data transformations.
> > >
> > > I'm trying to better understand what qualifies as a "stateless or
> > > low-state function" in the kernel context. How do we define or identi=
fy
> > > whether a kernel function is stateless or low-state?
> > >
> > > Also, I'm curious - what proportion of kernel functions would we
> > > estimate falls into this category?
> >
> > I would define it based on "practical heuristics". A function is probab=
ly a
> > good candidate for KFuzzTest if it fits these loose criteria:
> >
> > - Minimal setup: KFuzzTest currently supports blob-based fuzzing, so th=
e
> >   function should consume raw data (or a thin wrapper struct) and not
> >   require a complex web of pre-initialized objects or deep call-chain
> >   prerequisites.
> > - Manageable teardown: if the function allocates memory or creates
> >   objects, the fuzzing harness must be able to cleanly free or revert
> >   that state before the next iteration. An example of this can be found
> >   in the pkcs7 example in patch 5/6 [1].
> > - Non-destructive global impact: it's okay if the function touches glob=
al
> >   state in minor ways (e.g., writing to the OID registry logs as is don=
e
> >   by the crypto/ functions that are fuzzed by the harnesses in patch 5/=
6),
> >   but what matters is that the kernel isn't left in a broken state befo=
re the
> >   next fuzzing iteration, meaning no leaked global locks, no corrupted
> >   shared data structures, and no deadlocks.
> >
> > These loose criteria are just suggestions, as you can technically fuzz
> > anything that you want to - KFuzzTest won't stop you. The danger is
> > that the kernel isn't designed to have raw userspace inputs shoved
> > into deep stateful functions out of nowhere. If a harness or function
> > relies on complex ad-hoc state management or strict preconditions,
> > fuzzing it out of context will likely just result in false positives, p=
anics,
> > and ultimately bogus harnesses.
> >
> > The goal of the framework is to fuzz real functions with realistic inpu=
ts
> > without accidentally breaking other parts of the kernel that the functi=
on
> > wasn't meant to touch. Therefore ideal targets (like the PKCS7 example)
> > are ones with minimal setup (just passing a blob), have manageable
> > teardown (like freeing a returned object on success) and don't
> > destructively impact global state (even if they do minor things like
> > printing to logs).
> >
> > That said, I'm curious to see what you come up with! I'm sure there are
> > other use cases that I haven't thought of.
> >
> > [1] PKCS7 message parser fuzzing harness:
> > https://lore.kernel.org/all/20260112192827.25989-6-ethan.w.s.graham@gma=
il.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6wjPOoYemsK9EKrFM-eSpOgSUQvZ6kX5JyDTfC5J62Ufg%40mail.gmail.com.
