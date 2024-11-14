Return-Path: <kasan-dev+bncBDXYDPH3S4OBBB5I264QMGQE32VIGYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D149D9C87E2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 11:42:17 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2fb652f40f1sf3112281fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 02:42:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731580937; cv=pass;
        d=google.com; s=arc-20240605;
        b=aYA0QkIc6bd/V9IlINXydC30tUry1CqicSHwkhIT3LRuVkCP8b6V0G2LYsNkkGEcmz
         eb4uKXg4SQmFa7k4huHbxXWqlGr0VLjt+EfMf+9OqwL3nZPBiYQIt5muLEr6dX9Ou3oJ
         mIIiJ2c67nh/L7fPudgJ8WLczGQ6HDjaHRE2mvgpt5yc8lDkVUc4HGJMSKE1WFXprxJP
         XvhKQ2cyi60YOxR+KRCukgPrKjxMhmyY2waSv5m5if8lPZKI+64TDmp/Q1VGURBL87LZ
         QoF1fK825Cafz5G08DGvvL1XR8V/PkWMJorpANdDusvAVOW/IOtQ9NrsV1d+TBxqls64
         Wo8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=b2kMu284IzIPLnh8mQDlBfAzjed59C3QS14QD8lNObU=;
        fh=ldcAtp7XIDrk4QIb9sddyoNdwOSEI0yBxoHSKQ9OkEA=;
        b=flIIwqlFYFLV970GntTVvBqYW7Ab0EYY/ERejCW5C6qHUig3X1V5Gv54T6kubjURk1
         Q3B/INyJWxg0cMWk411JahuUKkXJ1nieMXPX2Hod/asMFrlXKYTJffG5j5nmSZTY6V9H
         ffysoE03kRcXBrI0ySYWaTHSG8IMIYWUtnoXz1LaEelHZ2LaS1qRIxdeYfKJ7fnEIias
         Ryl7MHZOoKS0BNGjDmMEec7xS01/H9x5uYDPWfIDJ4/z2Y/EmNfhk3bUJQj6C8DYKR5a
         TdIWxyLfSfBrETDK/Vfwb9iQG9zopbTusY3fqyJW0uVm90DNoLoJAWr6GFDYz3rMTx5g
         ehGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="o/WWCW0D";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="o/WWCW0D";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731580937; x=1732185737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b2kMu284IzIPLnh8mQDlBfAzjed59C3QS14QD8lNObU=;
        b=V1ErmwAHzqMPUqS2tp4pdUsXESKlLpo+o0budtyXY4fWZYitwGliEJtYInyY8QJnQO
         B1g7XlK/weKQ9f8QvFliZOUJHM6vT7QmOHkcqnGNduAA6EsCkwD5z3S6p0lpDAXi50uw
         bmxrhQRONBwh6D7Cy4hkkBDOSJA/se9sMFcWoj+APoCmvx4X/LtVBl9cKXYCydt/FfY9
         RRTW9Obn34/dpjP1PJfwDemvWnJ/6JhQpfvKCRxc+5YUIFy34MUSvU4IQke9DYVE2CTX
         vifhqjtXF0ezTxJ3RAc5ZrcJZWCjzhW6FRoJky0naET8YYg1e5g36gjI31l1MO4rvNRZ
         vxMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731580937; x=1732185737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b2kMu284IzIPLnh8mQDlBfAzjed59C3QS14QD8lNObU=;
        b=ONxbvrecWq1j5xfo/4wDGcKg2vOZU6dhUpNaVXIt9lybFOS/DPjxqVHGohYC+SLMhK
         xeOA6fF0mFZQUXVqAn1GS0E0RtH+0GphDXLgVuFqUgzfhOFm6HFmj+0PN35BCYQeRzEG
         8gbAkSSRe59IZyzvomSxSstUgRiBPY9TsyoCCAjEbavE/szW2OMzLkBamNxf7WOzOYKE
         mFMnE9cF57mYU3UtHWDhb2/vZHyoRY7l0ha7cEJJ4AKeTnyPdsT6SB/WYBVA07XwGefd
         R+ZKbK3aFVDVfg1nT5bzM+cweRh5HXMkndKGR/1BJKce5eQ8rf9p1GxBUCA1S+rzXOcx
         TQTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxMgx3nOHWQRqw7OlcBLzXVvcz5MZHDNNZQWLmdm40k24rwPX17BfW34cHfSVcmkBFMhQOyQ==@lfdr.de
X-Gm-Message-State: AOJu0YxBQoyOrjDhOajRN8ZWvY4GetyKz9aJln8G0npfOLB0AbwY+uVo
	SfrNha5r4V9uXxEvO585DqyC8KEs+BIOMWk7/VwN68HRldfJkte2
X-Google-Smtp-Source: AGHT+IGeqWRzGXDDQNlLq+F5twFH6/nYf1TOWijHt6IMfZdmEMeHRInEFely4zcjeYe7ErPqTRkkfg==
X-Received: by 2002:a05:651c:4011:b0:2ff:5c17:d572 with SMTP id 38308e7fff4ca-2ff5c17df4bmr3027771fa.22.1731580936248;
        Thu, 14 Nov 2024 02:42:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:478f:b0:42c:af5b:fabd with SMTP id
 5b1f17b1804b1-432d99bddb0ls2498585e9.1.-pod-prod-06-eu; Thu, 14 Nov 2024
 02:42:14 -0800 (PST)
X-Received: by 2002:a05:600c:4e08:b0:431:44fe:fd9f with SMTP id 5b1f17b1804b1-432da7cb853mr12407905e9.23.1731580934100;
        Thu, 14 Nov 2024 02:42:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731580934; cv=none;
        d=google.com; s=arc-20240605;
        b=ADgnttrvg2+/I+W5qj2raWtuLkd6x9wTHCkS1pTXtRqzw/dxR8O+s6epCe50tQr1qR
         ed3Vc0LnPyR4CxW3AjbDhe66D3NUKOyd+5L9zstpfYAbmFHm50oFYPufyMdbCcaArDUD
         EsPwlZapW6vhVPi/K+WTpuGjHXzLis418C0CAvlTdyFamxnti1+YU4YZn0WkUnNqbh7A
         OxkB6fd65+NK6ATIsf5GFRn5WxppmkAcClGgNLisNDxf9s3hPJgYtzNlrqYoktHZrIkl
         bRivdR3K4i3vJNN9JRE//tcJMpyrZzZzAf0bHVNam2civXolaFqVH8LN2NfKgeedSCuQ
         w2FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=hDmbYNzWsci4PxZKuq25OJU12sv+lOWhhjNx9ffNUhM=;
        fh=pTxV1gGlee5Oxu4RA4tdUGc0Bt/BOe25TryvNOVk05Y=;
        b=AVkUoFR5L1B16Lc9haG1nYAo8QjcoFeBw0zOSUhbDRsIpMsCfuAd07QnyulZ20z+bf
         dy32UixYsb0039E5vX4mgnmYz/FqM8VYmmYd4chZomAVid0Ou2ZN72VT1TekW+eeQoYa
         XgPaZSRy9W64/SKsT3AII1ZdMFM124MTREK8dW6b6FW+lqn2JBMlVf5p3YOTZzCys3Yf
         z4D8kguOdhjGE1+gSSCK/hco5p19rY+EVmrwWea2bBgbFQ6+rXjqHFR2nZ6oUUc2eIqW
         79haUsn5n3C9aE/tVT5ZFUBl+1ijF6yytjWOl8uAes9JAZA9KW4PMhBnCU7VOVJHQ47H
         1LYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="o/WWCW0D";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="o/WWCW0D";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3821ae0e92bsi20382f8f.4.2024.11.14.02.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Nov 2024 02:42:14 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8C65B1F79C;
	Thu, 14 Nov 2024 10:42:13 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5475D13721;
	Thu, 14 Nov 2024 10:42:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8kr9EwXUNWfCJgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 14 Nov 2024 10:42:13 +0000
Message-ID: <80d61508-f714-4d4c-b8e1-b5c0db6adbdd@suse.cz>
Date: Thu, 14 Nov 2024 11:42:13 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC PATCH v1 11/57] fork: Permit boot-time THREAD_SIZE
 determination
Content-Language: en-US
To: Ryan Roberts <ryan.roberts@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Anshuman Khandual <anshuman.khandual@arm.com>,
 Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Catalin Marinas <catalin.marinas@arm.com>,
 David Hildenbrand <david@redhat.com>, Greg Marsden
 <greg.marsden@oracle.com>, Ingo Molnar <mingo@redhat.com>,
 Ivan Ivanov <ivan.ivanov@suse.com>, Juri Lelli <juri.lelli@redhat.com>,
 Kalesh Singh <kaleshsingh@google.com>, Marc Zyngier <maz@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Matthias Brugger <mbrugger@suse.com>,
 Miroslav Benes <mbenes@suse.cz>, Peter Zijlstra <peterz@infradead.org>,
 Vincent Guittot <vincent.guittot@linaro.org>, Will Deacon <will@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org
References: <20241014105514.3206191-1-ryan.roberts@arm.com>
 <20241014105912.3207374-1-ryan.roberts@arm.com>
 <20241014105912.3207374-11-ryan.roberts@arm.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20241014105912.3207374-11-ryan.roberts@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[arm.com,linux-foundation.org,gmail.com,kernel.org,arndb.de,redhat.com,oracle.com,suse.com,google.com,suse.cz,infradead.org,linaro.org];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[25];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:email,suse.cz:mid,arm.com:email]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="o/WWCW0D";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="o/WWCW0D";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/14/24 12:58, Ryan Roberts wrote:
> THREAD_SIZE defines the size of a kernel thread stack. To date, it has
> been set at compile-time. However, when using vmap stacks, the size must
> be a multiple of PAGE_SIZE, and given we are in the process of
> supporting boot-time page size, we must also do the same for
> THREAD_SIZE.
> 
> The alternative would be to define THREAD_SIZE for the largest supported
> page size, but this would waste memory when using a smaller page size.
> For example, arm64 requires THREAD_SIZE to be 16K, but when using 64K
> pages and a vmap stack, we must increase the size to 64K. If we required
> 64K when 4K or 16K page size was in use, we would waste 48K per kernel
> thread.
> 
> So let's refactor to allow THREAD_SIZE to not be a compile-time
> constant. THREAD_SIZE_MAX (and THREAD_ALIGN_MAX) are introduced to
> manage the limits, as is done for PAGE_SIZE.
> 
> When THREAD_SIZE is a compile-time constant, behaviour and code size
> should be equivalent.
> 
> Signed-off-by: Ryan Roberts <ryan.roberts@arm.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/80d61508-f714-4d4c-b8e1-b5c0db6adbdd%40suse.cz.
