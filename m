Return-Path: <kasan-dev+bncBAABBTPJU7GQMGQEI7I7WBA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OnDbEND0qWmcIgEAu9opvQ
	(envelope-from <kasan-dev+bncBAABBTPJU7GQMGQEI7I7WBA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 22:25:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C76A82187C8
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 22:25:35 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59e16c11f49sf1849808e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 13:25:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772745934; cv=pass;
        d=google.com; s=arc-20240605;
        b=kk5kP0tnQy5XiMWU2fsPD+plAsoAHvsn+7QEyVClXff8hU48dGmeY9CY+G/vBOZjN1
         fp8WyO15Et1zVqyAMuz/C6hZMmY/EDJGi1S/OT9QCM/q8cKWDlvLOhnx7Upe4uHkY88v
         wutjplZiypw43kmhYwIfowkbEYFWNx4BEeSlyg0qAR6GqS5RbB92DHMUMmra4qW8JjGw
         1+R6zsKVwltnmZjhccEwxPtBjlbC8JB6PCCxBsj3Rw5DzQslB3LG+E4M2wO/XafNVwLG
         2i06wL/SJi8DM97akwbQWTvTcysl7u5Hye3y4psj5tb4Cxt02lBwcfP66P7YN6T1TFgn
         BNjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=s9Hocne1XFj7v+QJAeWKTs/Wrgba+8ancEWXCNfMn/w=;
        fh=gosFi8os8E2zMTcBu1urGpYQmlX14qqt0uLd8w/k52Q=;
        b=MR35Pr/2w5d84kjOL2OHRo1ZXrCFoqVG1ZnGjehKFFFJaCcrNmu/37JPpWIVl6WG1K
         ilYXiJi4pKPTAZUAse5va5VytvsjEavMT56yLEj7eJZmrSW7Iu87vyFB1RK9AbUix7SW
         PLxHwBIIzRR/LZqlkVljEvyPjEYAmso5bx3mhd0Hc14OhxV7dqwODg41kfrCAjmMr+wa
         FBU0uD91NDYOLgmP+V/yPQD3X3RQeyLWXiPUBGH+69h7l9AaEGjlKUgKNE7qMJtxlN2K
         iavutXck1220FF3bmP2f+/KmcmXL+Htu9vcndsjzVB6/hjFBqJzs4Ahiceww0DvbI/xL
         6/Bg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="D/mneLLF";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772745934; x=1773350734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=s9Hocne1XFj7v+QJAeWKTs/Wrgba+8ancEWXCNfMn/w=;
        b=HDz8ruDg6kCrPwNu8DgEYCecUkzStWhlqcWXwlF8odyjsil2rf1LjvXUZOXbwVOeQZ
         WmmXov6jy9kwOqZNswnBpelKEX9FOfEgNTX7oroOl1dab9jTcZdM54tAmJQtMQrOMK22
         SFAWPfEGs+pfpjGXCHLBJwYCBnfHV/Ibo+dZq/kJAn6dKTCVvCMUzW5z/S7t5JLu/aNo
         FecvLgONhjm0jDHuZhiXVOLZJKGvqXid6czAxh9rdo6LtupUQU6slYXjCRMV1yFSj2Mf
         4BKonUIgvuT4swOlTO33Or/0R8A+Vw5mwZfrhUPTCJ+vDP4kY7ATk0pWnjXacItgELvr
         SnXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772745934; x=1773350734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=s9Hocne1XFj7v+QJAeWKTs/Wrgba+8ancEWXCNfMn/w=;
        b=RwCwUezOhSL0zMnKD/x4eenAGL92xrht+q4jmzsXKjY95nbXZvN28xO08Fq/eDArJP
         nK796ls6Hva+ELxITENE2C4ES5Jxo6ujvxAVvi7C4Rc1c4L+8kuSUHTv1mRlsFFD/hPf
         Rg0MOBw5pNIyXGtewfQNUSCtRbJaPGibi1vqasGOSIyZq9mxcMbEHLNcGPFHalBN4+bI
         gowe1Xw+VYbLevqsWmIeC5evqm5JrkdsQGuS1YTgj4UGPXwKy9ZYXciiygOmz/njMfOu
         6sERZ34XpvO2ekqS1FEmZ4jSLnDYtc/BJDGzjnDZwOVpaQdBzrhVvWQXkj9In7LNxrAf
         ZUlA==
X-Forwarded-Encrypted: i=2; AJvYcCX819i9GPld/HVbZcrrSCPAdZiZhRD/8/peubrEtV5ZlwWzkTvOTdYMcwaoV9YI/i3SSDBY8g==@lfdr.de
X-Gm-Message-State: AOJu0Yz7ccMfyAy5G+lwiP/R0DiJLpV1VWc9MIOoLsdM0ePfetafixuB
	yyqKYCCGB3MYrI8rnXpmavwJBycI2/4SQWNtGuQrQp9feSpbHOrqe7Ok
X-Received: by 2002:a05:6512:3ba8:b0:5a1:1d8c:42a6 with SMTP id 2adb3069b0e04-5a12c2eaea7mr1418907e87.4.1772745934229;
        Thu, 05 Mar 2026 13:25:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Esz/mxP/kV2emQ8gdL/8DRbwxWm5ls1/rHl9LVWydwAA=="
Received: by 2002:a05:6512:1155:b0:59b:6d59:3201 with SMTP id
 2adb3069b0e04-5a12fbf28e4ls282271e87.0.-pod-prod-06-eu; Thu, 05 Mar 2026
 13:25:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWHscvtpvn7kPJtKLmjS3/Y3O8Nw7JZhsPs91lfhsY8YiZNkSVehZux/4rOYp9wU3CDH9q31+ozzHU=@googlegroups.com
X-Received: by 2002:a05:6512:3409:b0:5a1:3b7f:450e with SMTP id 2adb3069b0e04-5a13b7f4549mr33738e87.42.1772745932095;
        Thu, 05 Mar 2026 13:25:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772745932; cv=none;
        d=google.com; s=arc-20240605;
        b=lBP12crFdbl40mUO1jS4ZNDMc4UDQQFpKjsQMVHE7PhPm2tYtbh8C/imND1I4r/VnP
         +42cON0sb1zXOa59KcUJ8q1Dzh9mYTHms+HygItYj9eSGkXcSNurNSzjwA0VbOfO4r5N
         o1qZu36jGcEPqDc0gKQrhhcPiSJq0FC2WMTFY3xiwKFFiMfuxQNPVBueSMGHr+UQrY11
         y0Dn+BLRK8gyGXBJAwU1jaqVosTHIFEDEg40RDL2IZ1XttYbNRQkj7zyZJdgIv8qBIaZ
         RIgXUHBPLf6czHT5XZwHV2LiSCA/bpkhJrTz5meSTKenPnggu4oPnxUnVFaKpokVCZRA
         m1UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=TPF/Q7ncQZcbDUXuzcqWPm9P90x5P/esUaASP+y1v2o=;
        fh=rQoAgTABpoxH/VIG/SflDEM6gsnZB6YF5HWTrcKIoVg=;
        b=TfWNq4SBXIyp0Jp1shfC19bueT6I6vBMUxR3bUWo3wR7jAYPlB2RuGIfPhfQ1R7H0p
         SN5FBMwvYrkurnKLWmbMR3I/hMyBjWlQZWegpJdYQjausA2+BHVL1MVAMFVnV3Y4ONnA
         0fkPQ4BXBSqdE2urMUwzE2jeYCb1VKbDRPjBWRqmVBs3HQfY/9VkziT6eMocyuXhU/2+
         l4e4P1S4ACLgocYLUO4b30x5n4RpuDRz9LtdHOAycUMnzvU911pgsPFtWsi0sZVWPINJ
         kZxbqfPo8HtdN+L/FZ1wMmH3+dH+FrnTaQh5OOBmx7Ka4QWLKVZxwEChf1M8e/2dkYYT
         cEkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="D/mneLLF";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106120.protonmail.ch (mail-106120.protonmail.ch. [79.135.106.120])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5a117e0188esi408466e87.6.2026.03.05.13.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 13:25:32 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) client-ip=79.135.106.120;
Date: Thu, 05 Mar 2026 21:25:26 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Jonathan Corbet <corbet@lwn.net>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, workflows@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v10 01/13] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <aan0qbP0iV48bih-@wieczorr-mobl1.localdomain>
In-Reply-To: <CAPAsAGyiukChPLYO_tQci-7Bvmnnxh+w=bO6eUYLrO3RVuUThw@mail.gmail.com>
References: <cover.1770232424.git.m.wieczorretman@pm.me> <bd935d83b2fe3ddfedff052323a2b84e85061042.1770232424.git.m.wieczorretman@pm.me> <CAPAsAGxpHBqzppoKCrqvH0mfhEn6p0aEHR30ZifB3uv81v68EA@mail.gmail.com> <aanievpHCv0Sz3Bf@wieczorr-mobl1.localdomain> <CAPAsAGyiukChPLYO_tQci-7Bvmnnxh+w=bO6eUYLrO3RVuUThw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 2a85cbea50d69490acd671149ee415089f8f199e
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="D/mneLLF";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Queue-Id: C76A82187C8
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBTPJU7GQMGQEI7I7WBA];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[24];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[arm.com,kernel.org,lwn.net,google.com,gmail.com,linux-foundation.org,siemens.com,sifive.com,intel.com,lists.infradead.org,vger.kernel.org,googlegroups.com,kvack.org,lists.linux.dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:replyto,pm.me:email,googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

On 2026-03-06 at 06:22:32 +0900, Andrey Ryabinin wrote:
>Maciej Wieczor-Retman <m.wieczorretman@pm.me> writes:
>
>> Thanks, that looks really neat! I should've thought of that instead of m=
aking
>> separate arch versions :)
>>
>> Do you want me to attach the code you posted here to this patchset or do=
 you
>> intend to post it yourself?
>
>I think you can just squash my diff into the subject patch.

Cool, thanks, will do!

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
an0qbP0iV48bih-%40wieczorr-mobl1.localdomain.
