Return-Path: <kasan-dev+bncBDH3RCEMUEHRBEUM37FQMGQE35TATSA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cLnMGBTGd2nckgEAu9opvQ
	(envelope-from <kasan-dev+bncBDH3RCEMUEHRBEUM37FQMGQE35TATSA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:52:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E3C2E8CC89
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:52:51 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-385c73b50dbsf23544541fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 11:52:51 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769457171; cv=pass;
        d=google.com; s=arc-20240605;
        b=hg7RtK/s83bhLpFO8DhZKYYUMCqWSyWu1USKyfVCBP6+Pwjb6jEiax8/NrRVLXFHwA
         XsTnF6se7LYEqi+IF2eICbg/8yAtyxhCwvowpBZKBVAunHyfuaaJISEJkAkgg9YQC98y
         ISlpKUVQ/MgVXpAlbjiiZ0K9jU2lbe8eEFucU3Im8kay935XU0Gs/Aft8/q1OgPBB0kB
         pAYbYEll/pzmdD5MIKe4LX5XECOxvAHzfSVH7wB9kgDLEKn+nmLztYZvGM/KTR0nIS3e
         fVm+OPuuG9Uhxoub9KM3Yg6yOPJHqogAzs1P4ycz5ybaqFDLSBFH9s0ojx3tQQl+XN6Z
         qsiw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=db3l73n+4DTWM8vMi4BbUtR+qOh7xIv0fSk2KwfOwx8=;
        fh=3EuEIN7/B9Tl1rcZFRT0zpPwalV3gNJhOgYvqgRoyzI=;
        b=Py5KrA8mKYvkNjd2Yj0WD9G2x+IF4iIuIy1MV/VgGtrqpywOedEakPa0m3MEWYBTWX
         OvwcjfC4Afo6E4Nw6YLuMqrDgVxKN38ou6vESC49rCsccDZO2ky//fzm1Zetbt36l2eV
         VIcL9e6+BTfjmW2bj8PfYDAlAxnNwrQi1qQDDMRqfBt4ya5NpnNNNNpEfIg0mlp+9kam
         l37bTLRKgBp6SPXlM/4Egjgcz8cDC8/u4FQF8iF/MmeZE7b/Fd1FqmegGeFkPvx79sYt
         wH7tNZ9zZnu4oTcp5MfbtJS2C6qIQOVOqM/f0FnbPKAzUvvt1fTNsqd/rB6Oaup96u1h
         6Z2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GMSvR0x+;
       arc=pass (i=1);
       spf=pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769457171; x=1770061971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=db3l73n+4DTWM8vMi4BbUtR+qOh7xIv0fSk2KwfOwx8=;
        b=sZ57dmonaf5bjVFDmX07axZeRPAFVCWlk96ZI944eawzKm8T8bqy6T6vl0EGmWoqQR
         DMgWq3Qulk0pjX0p/vOiEbGGYPyjLXZN2rrionycDvOCMZDy3NnFVPD8eGHFIlLYwRze
         voKaUO5g+kHjmvew2BDkO8sSJLthU9Vm7ae43q8xnm9k3h5GkzOtml0d6LTNih4zTuhv
         TpsdLP0E1gDQHYK0UQivbLriZeeVFc0zc/VLe4IoeOOLIL3O6+T2mnp6YAiCSYzjNPl8
         c9GYBbGpC7/lIZMizReySlM8gsuOhHgzK3ttvc+DI/a6tXt+riwAr+wi3kWvXyK2Zzpf
         N3Xw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769457171; x=1770061971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=db3l73n+4DTWM8vMi4BbUtR+qOh7xIv0fSk2KwfOwx8=;
        b=YYXjbOkipeYipB9tZY98wZL5EKGyFWlm1NlSsAHJ7qVSh0+GJHkw+1oimTwJ5Sz/b0
         51x0Y1Cs8pe2iMpQNuUvO/4dF+Q8q3cNlEBq6pE7+W7lHrNRhRibC7dF5PWSrFXWLZll
         MHRHa/ShJwGXx72dZT/8W3uIT+l4S8mf7CEV5oEE+Ccu/Jacjwgh6SfdQgHlRVgm38dw
         6hKVqx7WKC9umKqhklsY7wcFnu9Wt8QZIkqyCaE2CnihD+aEqkCjE0US7ha4HFt6cjZ2
         L6SR85X8kXTMjbVrwwJ821vMSe/jpuRiyqyCKDf67w6ZkasKVtBroL1JW3uuELofkDem
         eHcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769457171; x=1770061971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=db3l73n+4DTWM8vMi4BbUtR+qOh7xIv0fSk2KwfOwx8=;
        b=ondQ23QfDdLDhH90Bx1h2wXRoBxr6Q/DAXWjcixCA8qmvehiwaj/d8ThnRwnoKKtLv
         6YZKzDsXY0RpETxGJcFjjx14y7bZnYMkWUG3XG8cf7b9/4U8tZdW5dDpCNf7/M8YzK2C
         uufBupAPzt9Jy5k76aG4pXyoG+WAMknBAOib5yUSh21dSkl5UnErk8ws4iUJR7Ypphb0
         Qu3mtz+Yfo9FR2YbRGSYRyzZwP7A9FrO/jrKHzOmEKoNcXnMWH/Y3tfiJHEXLlaj6otJ
         kj7VesX4hJ3RtBvrhaPxrUVzF9oc+uc680CYf1h7hNXV21uninTuDag2kdM7juzuvKfp
         mEDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUj4c81PX1MRzapqg2TG5PAeUCKiIoYldm19Y8UydHiYOUEle2qyn/xnJBiDLD2OfmLWJ45xQ==@lfdr.de
X-Gm-Message-State: AOJu0YwaSiAeqrQgVlYeegHIOuPmNjtrItkifufaF7zLk2G0OdRgbESc
	TYh0r+5e/RuLEn9AnJMx7z5Sxqt558B9UeXKaZWTajS2o/6fqvFu8jt6
X-Received: by 2002:a05:6512:2215:b0:59d:dffb:cd7f with SMTP id 2adb3069b0e04-59df35ba335mr2311454e87.3.1769457170791;
        Mon, 26 Jan 2026 11:52:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G+quBWDGzKcCmWh+UoOW8uLvJZ6fcRYwWLlLAzFyNGSw=="
Received: by 2002:a05:6512:31d1:b0:59b:739a:3ae4 with SMTP id
 2adb3069b0e04-59dd7986133ls1420286e87.2.-pod-prod-00-eu; Mon, 26 Jan 2026
 11:52:47 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV/+GjzBpF2nWxCshK6g8z0E5QnADgCWsN6Wm+dQvY6zZIxj1XhtNMaEWYqCkYwWlc1wiggHWMJIKs=@googlegroups.com
X-Received: by 2002:a05:6512:12d0:b0:59b:b021:6033 with SMTP id 2adb3069b0e04-59df3a11023mr2102822e87.25.1769457167470;
        Mon, 26 Jan 2026 11:52:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769457167; cv=pass;
        d=google.com; s=arc-20240605;
        b=N5D4PZK3Ut3OCoVghta3U29Gn/fRzEGkO5RDcj6silUaaihb8dD/go+DpOfakZvnZd
         SrG33BD6DxHuRaRR2uoiPWeQvouVDhOFm96eVXjF4fx3vJgX+zDn76YhzZklNNcMh051
         dNdwnTn4S7Y/qXrufL31AgSV9hvYYIYDbRmtqvjCdYbUJzA8tST3/9zT1jOGyOPf+tzv
         GLrGFAjw1Fq0njOdWkFvXSQXuyZN5J7aWvhbMGC06GXahdAPS+ETbUKwJj437ut3Fhd0
         TMVO2+VOMcsS4tnzVMXGhwi6HUsg2nK98dC1r0lSR4/OoIKbaNxtNs11YOO1QYSOK4yh
         vTmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oMGWu1cxUVEHtMuACd0uKIBb6HVqMLlmxpyjks3jTsA=;
        fh=3CF8bLGXVGKCe2QMCaV8/qw6CwpT6vQe6T2T26cnUfI=;
        b=YonPIjr2L77A3t6kYH0W88it5NWXtnRdr0SWAhpUBwZL2BVAvGRTxIiUi+xtnC/qS5
         z5oOetLKkOTpWx+j72oNTpljwG2iKQSsIoqEdBfd9GS0dV2Yev4B/ad1G7DT/LvYNFYa
         qKZ0SZl0tGwiGJD+LZTIuY6r/7tUP0JJAx3sopuEFrgfbwWi/UsQnNsNRcLtE28sp10I
         p5qR+tYmcSxYBlYxhjLKulUA+TYKU1U+dUGASnUOQ6Pq61VE6tx5hQE0tVwbLnAOAoo/
         YeNjpdIIDNU9V+gpsemqWd0xvHyH2LtDPRp5Mq9kDCm1DsNQy39o5vxiwqUxwmImolue
         182w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GMSvR0x+;
       arc=pass (i=1);
       spf=pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de4908130si287592e87.3.2026.01.26.11.52.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 11:52:47 -0800 (PST)
Received-SPF: pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-59dcd9b89ecso6022473e87.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 11:52:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769457167; cv=none;
        d=google.com; s=arc-20240605;
        b=CEio4pmRjh4qHBySv/311VgrNmfV5dSyomkYL3l/zHY11b+jyz+REC3c+zxJkQOgiB
         GUYvlSyUxvZ3CvZCDvr7XfoV62K2uw9QNKwjqw91UXLAxKC11tZAn7sQ7raM0VWOSK8d
         QTyX1gucM5EPSpCBUM8gkvF7F0PaJ2Aiwi/+uFpS71wbX8RhZzyA+14kMcIaheOwzfJk
         BO0oQhItv+fqW4f61PKD3tje3fP21jj1vV/URVfa5eh6oiSp1nldl5DopREra9WevSEd
         ghguiQdIydExOskSxfSLxrmum5O3JJI8YhGK+kEM7ZwI9CC4fcCuKx2/sJSxOPg1kEbh
         Lwxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oMGWu1cxUVEHtMuACd0uKIBb6HVqMLlmxpyjks3jTsA=;
        fh=3CF8bLGXVGKCe2QMCaV8/qw6CwpT6vQe6T2T26cnUfI=;
        b=GJEtE1qK5b5re/eTbnyTK4+h+tZKdxdrFIVhgQr9DuXW2wkvLfror4yBtpPammnLBs
         yhSwgSQVWXcb9NYaUP1VtHwmdDr3zn447aMzm2ZbQufq5HbrnnOfZdgbqUsRFQGwej3F
         4sxg/bLYnWFZZIvNPmfCEzrMtcEKbUclXDOJVPflVM7rcYatDrXpgbp0ZFoZLHk1Rtzr
         gDJMP4VokHkTHNnoeDiFO5Tgn5LQNzElBaZ/kGo3yleCD5GMW39swG6Gt/DXd7kflGVc
         hJTzpOqcv7GiwnrKZajRiRRijPUBzwtpPZdHsdJqZLzgh8bWwU8vrnbvrGgyofbZNfv4
         66SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCULr0Ay14NSkNwx7K0rMICkFq8b2fg/rWoYcd3J7hzSm8gAR7jPcimn8l2cAmosi40Rzf7N7yljZ7s=@googlegroups.com
X-Gm-Gg: AZuq6aJJp00zWKTz1SAKlWmz33fGE8xxTN/jUdvvItIUw8fiJPgV7FeLQDTkCyGtgSX
	mGgXBNfnD1zyURF3pP2KzNhylV34dvmvmZP8b153ioMcmzDJWDs+hcdNZzkhMCw8b8x+7fBY4N0
	/9GFmS6IfZ2Mf2X64U4Smbt4s0y27mCmIDS2mke8wzRQQfOWZU1FCIEoVtdvyghKthJHpmZ7MmP
	UTPcc/p4KKIZXZnWG3yUDSAgmbv5lozK+8eS3olRLttpwddpZukAqC8Ao7hjHgGnv/xFGas
X-Received: by 2002:a05:6512:b0f:b0:59d:f5a8:271 with SMTP id
 2adb3069b0e04-59df5a802b8mr1632496e87.10.1769457166707; Mon, 26 Jan 2026
 11:52:46 -0800 (PST)
MIME-Version: 1.0
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com> <062eb8bd-3d98-4a0a-baf4-8f59b7643041@citrix.com>
In-Reply-To: <062eb8bd-3d98-4a0a-baf4-8f59b7643041@citrix.com>
From: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Date: Tue, 27 Jan 2026 04:52:30 +0900
X-Gm-Features: AZwV_Qgn8uYrhYJYP6NWCn-bWS5cMvXlxHVBl1BNLD51V2c1UA2Y7BLWYdThW8Y
Message-ID: <CAKFNMok_hSMoJJcFUOSLPNcyHUD+um99Botn3B9YbBYYZeKvRQ@mail.gmail.com>
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: konishi.ryusuke@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GMSvR0x+;       arc=pass
 (i=1);       spf=pass (google.com: domain of konishi.ryusuke@gmail.com
 designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDH3RCEMUEHRBEUM37FQMGQE35TATSA];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[14];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[konishiryusuke@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-lj1-x23e.google.com:helo,mail-lj1-x23e.google.com:rdns]
X-Rspamd-Queue-Id: E3C2E8CC89
X-Rspamd-Action: no action

On Tue, Jan 27, 2026 at 4:39=E2=80=AFAM Andrew Cooper wrote:
>
> On 26/01/2026 7:07 pm, Ryusuke Konishi wrote:
> > Hi All,
> >
> > I am reporting a boot regression in v6.19-rc7 on an x86_32
> > environment. The kernel hangs immediately after "Booting the kernel"
> > and does not produce any early console output.
> >
> > A git bisect identified the following commit as the first bad commit:
> > b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
> >
> > Environment and Config:
> > - Guest Arch: x86_32  (one of my test VMs)
> > - Memory Config: # CONFIG_X86_PAE is not set
> > - KFENCE Config: CONFIG_KFENCE=3Dy
> > - Host/Hypervisor: x86_64 host running KVM
> >
> > The system fails to boot at a very early stage. I have confirmed that
> > reverting commit b505f1944535 on top of v6.19-rc7 completely resolves
> > the issue, and the kernel boots normally.
> >
> > Could you please verify if this change is compatible with x86_32
> > (non-PAE) configurations?
> > I am happy to provide my full .config or test any potential fixes.
>
> Hmm.  To start with, does this fix the crash?
>
> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.=
h
> index acf9ffa1a171..2fe454722e54 100644
> --- a/arch/x86/include/asm/kfence.h
> +++ b/arch/x86/include/asm/kfence.h
> @@ -67,8 +67,6 @@ static inline bool kfence_protect_page(unsigned long ad=
dr, bool protect)
>          * If the page was protected (non-present) and we're making it
>          * present, there is no need to flush the TLB at all.
>          */
> -       if (!protect)
> -               return true;
>
>         /*
>          * We need to avoid IPIs, as we may get KFENCE allocations or fau=
lts
>
>
>
> Re-reading, I can't spot anything obvious.
>
> Architecturally, x86 explicitly does not need a TLB flush when turning a
> non-present mapping present, and it's strictly 4k leaf mappings we're
> handling here.
>
> I wonder if something else is missing a flush, and was being covered by
> this.
>
> ~Andrew

I tested this change, but unfortunately the boot hang still occurs.

Regards,
Ryusuke Konishi

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AKFNMok_hSMoJJcFUOSLPNcyHUD%2Bum99Botn3B9YbBYYZeKvRQ%40mail.gmail.com.
