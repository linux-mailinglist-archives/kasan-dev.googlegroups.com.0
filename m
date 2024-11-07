Return-Path: <kasan-dev+bncBC6LHPWNU4DBB2ONWS4QMGQEI74YJRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D4F209C0FF1
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 21:45:30 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e28fea2adb6sf1908233276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 12:45:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731012330; cv=pass;
        d=google.com; s=arc-20240605;
        b=edhFg5lMEn5siXPs2KYZD0FD0OnQxotuVpg8OANaSRXEcavMaF57YMznrAyX+uOvJw
         B+BoNdsnt9gfyHi81ajQlpWJ6rJ79d5b1Ipep1kbnz50wXXbyYOkIOO+YMB1JSVQY0vo
         Fq7brC/Bqc4JHl2fOdbKFLPUmz9/3gaYdUBJWVm7m3sw3c30uPLgOM5ZmJk+BBzON4/9
         BVT8vG8yAT3wfaeH4E6KW2kzXpXA94qnoQeMJ7oKoUhQUEU5Dq30ulmEZC9IT2TrUJwo
         clCdSl8Gd+acsTvIFMHqkSABMLEhUya2Zyg5X66lG/Hz6ScFSHEX728X4gGRgHmwyKxN
         zddA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=JeE54DIe25P+19WPvwcGSykftNfSipYszPg41brmio4=;
        fh=19eeWGL+SgFmt9TaUYC9voF1bij6NDoNwsIUQLDeI7M=;
        b=MzY+QecTA3Di+OU25tytl0xlrBbcgHKQolYF9RCxAgR7Up5m0rzfVi+NFcWAbKQm8E
         ALAytIzlE3oRTTyCO/kopSLNK7iUywA//kJYd3pjNtQn6n//AJm6EUeKrk0EzfL1+dAx
         LcCepYdCnMmyQEVlnsIwipo5gP12tvxLVQHnE1b9cRoik+rKyqr2ua9Ibuufh8RYEZDR
         hQWV97IbXdEjBIiS0DPxfhbSYIykBw54kqIrFXTpibvdS1Meake/VpbUK9OlbNPhYCaN
         fWQJgyDdXCv4osu0TQi/VBlSd5zQjj7w9k8rz11LkpcCUd3rQSA32cg39mJ7KErmINPp
         L3ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RAgV65F+;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731012329; x=1731617129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JeE54DIe25P+19WPvwcGSykftNfSipYszPg41brmio4=;
        b=Fr3P75gOQKFrum6apmCASlB/awBvV1X2V3LNHwbRlI9e16fqeDXJpBW4ZE0dNNz0Wf
         399p9XvaWZAnrrlqnH6U1Luf9SwTsquBqajxHNfrn6HiM/cPHM/5UTGeOC3LUsRZKyTP
         tEgdd8uLg3q01xNjjPHfyQ1OdrpOc0A8+2nXatm5BV3kQ6ZP+sk/96ciClnvSwvVXKiO
         weXU8xtW1jMKFm9WU9Q7E4oPYm5VGXH541/ns2TgSnv+0RnyX18nPnDpUGc1iSRb4YgR
         8pu7ckmjDoPJN2Ek12j+tsjFjRRVPGoz+X1xPpV5YuCdpKwsHQT3t4pYn8o3IhUbv7E5
         4Oyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731012330; x=1731617130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JeE54DIe25P+19WPvwcGSykftNfSipYszPg41brmio4=;
        b=SKn/+OTynPv+RGMQdljAU52fNsTPF3SR8AhvM03MhHLWj+jmiEC0YW6AbQh3l46Ix/
         xsXg3QZ0Bzc+lFufB5+s50kvUyKexYTERAvnFjnZkyZKxfK3aUeXKQYpGbIx3T09Lg5o
         PSKjE+430/+i8iNY9l39GQFP6FxynOd1tCcmAxlDHBagpw44ILzQ81XXdlMJg6tMayaC
         wIMre+uIxjc5gZoN7zArLmSHqgqFEhqCIlgm1WYAEvz/HDvmyIpPGbfoqJ9xxEkzRSep
         vZWwRv0MiRoGIaL8YtP+bQrK4nrTA9zfKzA0rPmZbpCnZB0Rr/+mCHCg90CjyoXlg2Kv
         rS1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731012330; x=1731617130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=JeE54DIe25P+19WPvwcGSykftNfSipYszPg41brmio4=;
        b=rM+0BEOgZGShawr163RM4MHqh4RVso7hkFpEu2zErfjTNGGoyBw9rgnqbeKefT/3Ko
         aqXqLGfRT54ARccPhsSr8cUQjp+vo/6bAwnitgAwWBm3kP+fLfTxp4hTMBfTKSueioWu
         wvjQlStsb3Vt8MONy30cqYYJ04Y4nKENiAHdKweeOmouW5TpP3wGuOEOYo2cSuQv9S9+
         QzF15tBq3+sJuL2HhznYm/IPv7WK1r7aeN1x0oGQBhoaGTQesbjJfdIk6lhP/lAUxziu
         OM8eK8KKljxdSqL0QA92YYhSTJwTeZzOsnpXizT/KTRWxlQLHBqaMs+R5qS/PxBGg0n0
         IwYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsvrjdHYhAje/A+iujKxRbBAyY4d/Nxu1qmU1vXl6nILTN2Jkyg28O4blOBk1sAvkOpatnKA==@lfdr.de
X-Gm-Message-State: AOJu0YwVfXFXWrp2hRLYgqPvpfoplN2zIrrOkvou+gz8IBgPDzeXWP3k
	2SCVDlZ+jcGlriT+M7sQMs4oZEjX5LRSby1vYYH0ZlC2yVNIZGTW
X-Google-Smtp-Source: AGHT+IHiwTyMeKz5j94/iPTKQLwoMZWQ0x0EQ6nyRBa7K/IvS1cQuBw9BUGTJrpHz6FLRSFiZUWVjQ==
X-Received: by 2002:a05:6902:b0d:b0:e33:13ab:52c1 with SMTP id 3f1490d57ef6-e337f8f14e0mr381218276.35.1731012329480;
        Thu, 07 Nov 2024 12:45:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:181e:b0:e30:84f1:9a02 with SMTP id
 3f1490d57ef6-e3368014840ls1856076276.0.-pod-prod-08-us; Thu, 07 Nov 2024
 12:45:28 -0800 (PST)
X-Received: by 2002:a05:690c:284:b0:6ea:7831:e436 with SMTP id 00721157ae682-6eaddda3e80mr3642717b3.12.1731012328496;
        Thu, 07 Nov 2024 12:45:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731012328; cv=none;
        d=google.com; s=arc-20240605;
        b=Z0LAXqvB6CjNwH6h8MG6hdezkN3I71ItK/vge9b/I0ORPIntQ0wOqVvNH1UKr1u35I
         nJrmH3vhuX4S8gqgWBz3kFWOU5tD3sMU7xXvlOtZWk4RW/kAwz7DcBpn+zg2zv6i44xy
         sYGxsh+SGK3CxzS84rjkdmQH2lF7x6uEzKpzKnc25805sttrK1sZcoGf4tbBFqzDE5Cx
         qZkEemRLs3xuvnPkYnfOzRezGUw+8iCfMnpkVc4uJnb6FhTtOv40DBBvdxTMAzbJEdKy
         pysx+ehjWsysixcEU+MV5Hl5vviHCtWSLMhEkuOQHf5JnuDRG1m+53AF5+aDIufJqGy+
         BdAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=ASBXo4Z2Zrw1kV9v2x3uChH0kNYmBXHhzCm3vG2Xcz8=;
        fh=wB/Lt1I4u79n5LBJqB5IJWLA8T5MOF+P6O50A7DiuT8=;
        b=PYp+0DbgihUWuk8sNQdAZaJF4dNCrywAJGEor1RRE1j6k5X6Kvs9Ctzp7KL1FW9FDa
         iH1JfY6q3gmAyfmVThHPcbMpoSD1UXPMxfjI/HSYmYwigSjAXy0vT315Ch/x2Gx5T33g
         T6mzKPQRIGvY6IIIksOtN3+mie1Vy+ZavI1Z9NTlcbx1ZRc+qMM77q2eZPBL9A5d4LpU
         sTwmhgEDJuufi1UQAgCQrY90RWpPH9YOKrllbrSedhBvbS908em+bBYGfLeI5cHsHY+g
         2SeRgRFuS01gudfzNZiD+o07i+DnM4MvkitlA2sCYHMP+RVV+f2xi/NedQhPdJBQ1YHC
         tutQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RAgV65F+;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6eaceb3e8e3si1312617b3.3.2024.11.07.12.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2024 12:45:28 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-e30d1d97d20so1287082276.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2024 12:45:28 -0800 (PST)
X-Received: by 2002:a05:6902:f84:b0:e30:cd90:b631 with SMTP id 3f1490d57ef6-e337f8f0c61mr412352276.33.1731012327942;
        Thu, 07 Nov 2024 12:45:27 -0800 (PST)
Received: from fauth-a1-smtp.messagingengine.com (fauth-a1-smtp.messagingengine.com. [103.168.172.200])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-462ff5e14f9sm11750031cf.86.2024.11.07.12.45.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 12:45:27 -0800 (PST)
Received: from phl-compute-12.internal (phl-compute-12.phl.internal [10.202.2.52])
	by mailfauth.phl.internal (Postfix) with ESMTP id C929D1200043;
	Thu,  7 Nov 2024 15:45:26 -0500 (EST)
Received: from phl-mailfrontend-02 ([10.202.2.163])
  by phl-compute-12.internal (MEProxy); Thu, 07 Nov 2024 15:45:26 -0500
X-ME-Sender: <xms:5iYtZ4anBIkz8mLikFbtjBpK2wggB7G8dYkoRt3dv3RlgcCpH3Lraw>
    <xme:5iYtZzbU-3AWEINOE7FxrEAb7XmYh4YiNPoTYidsY3Gw0qGUpjiKN8bf_ajgQJIma
    72PH0wuF3h-5T_H0Q>
X-ME-Received: <xmr:5iYtZy83CsmHsGYC5i4fcVOey-J8cKZ3gDNF-gpZMJBdrtOS5etdJBUT0Eo>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefuddrtdeggddufeelucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggvpdfu
    rfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnh
    htshculddquddttddmnecujfgurhepfffhvfevuffkfhggtggujgesthdtredttddtvden
    ucfhrhhomhepuehoqhhunhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrd
    gtohhmqeenucggtffrrghtthgvrhhnpefhtedvgfdtueekvdekieetieetjeeihedvteeh
    uddujedvkedtkeefgedvvdehtdenucffohhmrghinhepkhgvrhhnvghlrdhorhhgnecuve
    hluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdo
    mhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejke
    ehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgr
    mhgvpdhnsggprhgtphhtthhopedujedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtoh
    epsghighgvrghshieslhhinhhuthhrohhnihigrdguvgdprhgtphhtthhopehkrghsrghn
    qdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhopehlihhnuhigqd
    hkvghrnhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehlihhnuhig
    qdhmmheskhhvrggtkhdrohhrghdprhgtphhtthhopehprghulhhmtghksehkvghrnhgvlh
    drohhrghdprhgtphhtthhopegvlhhvvghrsehgohhoghhlvgdrtghomhdprhgtphhtthho
    pehpvghtvghriiesihhnfhhrrgguvggrugdrohhrghdprhgtphhtthhopehtghhlgieslh
    hinhhuthhrohhnihigrdguvgdprhgtphhtthhopehvsggrsghkrgesshhushgvrdgtii
X-ME-Proxy: <xmx:5iYtZyolJa3NccFGpih2eG96Ilh61CmPZPHUGvGfb1J0rBx18Xos4A>
    <xmx:5iYtZzpTMAPqDfge5NwoWBh-uHvvLhKkr78apl0kN4zqRYVS1chj-g>
    <xmx:5iYtZwQouEz9J7IPFCKgBSDKpzRuhwdXo2nbCGW8o3ZcE_nli5hpAg>
    <xmx:5iYtZzozquyoM1X86TAoVl_h1acc23me483B8R58GyrD_2amDsZo5Q>
    <xmx:5iYtZ464pjyIiholy018iKlly8G9yT4XfRG6PHb3VTPHN6uqtu6rkqSd>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Thu,
 7 Nov 2024 15:45:26 -0500 (EST)
Date: Thu, 7 Nov 2024 12:45:25 -0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, "Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v2 3/3] scftorture: Use a lock-less list to free memory.
Message-ID: <Zy0m5TBz3Ne55syG@Boquns-Mac-mini.local>
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
 <20241107111821.3417762-4-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241107111821.3417762-4-bigeasy@linutronix.de>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RAgV65F+;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::b36
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Thu, Nov 07, 2024 at 12:13:08PM +0100, Sebastian Andrzej Siewior wrote:
> scf_handler() is used as a SMP function call. This function is always
> invoked in IRQ-context even with forced-threading enabled. This function
> frees memory which not allowed on PREEMPT_RT because the locking
> underneath is using sleeping locks.
> 
> Add a per-CPU scf_free_pool where each SMP functions adds its memory to
> be freed. This memory is then freed by scftorture_invoker() on each
> iteration. On the majority of invocations the number of items is less
> than five. If the thread sleeps/ gets delayed the number exceed 350 but
> did not reach 400 in testing. These were the spikes during testing.
> The bulk free of 64 pointers at once should improve the give-back if the
> list grows. The list size is ~1.3 items per invocations.
> 
> Having one global scf_free_pool with one cleaning thread let the list
> grow to over 10.000 items with 32 CPUs (again, spikes not the average)
> especially if the CPU went to sleep. The per-CPU part looks like a good
> compromise.
> 
> Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> Closes: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> ---
>  kernel/scftorture.c | 39 +++++++++++++++++++++++++++++++++++----
>  1 file changed, 35 insertions(+), 4 deletions(-)
> 
> diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> index 555b3b10621fe..1268a91af5d88 100644
> --- a/kernel/scftorture.c
> +++ b/kernel/scftorture.c
> @@ -97,6 +97,7 @@ struct scf_statistics {
>  static struct scf_statistics *scf_stats_p;
>  static struct task_struct *scf_torture_stats_task;
>  static DEFINE_PER_CPU(long long, scf_invoked_count);
> +static DEFINE_PER_CPU(struct llist_head, scf_free_pool);
>  
>  // Data for random primitive selection
>  #define SCF_PRIM_RESCHED	0
> @@ -133,6 +134,7 @@ struct scf_check {
>  	bool scfc_wait;
>  	bool scfc_rpc;
>  	struct completion scfc_completion;
> +	struct llist_node scf_node;
>  };
>  
>  // Use to wait for all threads to start.
> @@ -148,6 +150,31 @@ static DEFINE_TORTURE_RANDOM_PERCPU(scf_torture_rand);
>  
>  extern void resched_cpu(int cpu); // An alternative IPI vector.
>  
> +static void scf_add_to_free_list(struct scf_check *scfcp)
> +{
> +	struct llist_head *pool;
> +	unsigned int cpu;
> +
> +	cpu = raw_smp_processor_id() % nthreads;
> +	pool = &per_cpu(scf_free_pool, cpu);
> +	llist_add(&scfcp->scf_node, pool);
> +}
> +
> +static void scf_cleanup_free_list(unsigned int cpu)
> +{
> +	struct llist_head *pool;
> +	struct llist_node *node;
> +	struct scf_check *scfcp;
> +
> +	pool = &per_cpu(scf_free_pool, cpu);
> +	node = llist_del_all(pool);
> +	while (node) {
> +		scfcp = llist_entry(node, struct scf_check, scf_node);
> +		node = node->next;
> +		kfree(scfcp);
> +	}
> +}
> +
>  // Print torture statistics.  Caller must ensure serialization.
>  static void scf_torture_stats_print(void)
>  {
> @@ -296,7 +323,7 @@ static void scf_handler(void *scfc_in)
>  		if (scfcp->scfc_rpc)
>  			complete(&scfcp->scfc_completion);
>  	} else {
> -		kfree(scfcp);
> +		scf_add_to_free_list(scfcp);
>  	}
>  }
>  
> @@ -363,7 +390,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  				scfp->n_single_wait_ofl++;
>  			else
>  				scfp->n_single_ofl++;
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  			scfcp = NULL;
>  		}
>  		break;
> @@ -391,7 +418,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  				preempt_disable();
>  		} else {
>  			scfp->n_single_rpc_ofl++;
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  			scfcp = NULL;
>  		}
>  		break;
> @@ -428,7 +455,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  			pr_warn("%s: Memory-ordering failure, scfs_prim: %d.\n", __func__, scfsp->scfs_prim);
>  			atomic_inc(&n_mb_out_errs); // Leak rather than trash!
>  		} else {
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  		}
>  		barrier(); // Prevent race-reduction compiler optimizations.
>  	}
> @@ -479,6 +506,8 @@ static int scftorture_invoker(void *arg)
>  	VERBOSE_SCFTORTOUT("scftorture_invoker %d started", scfp->cpu);
>  
>  	do {
> +		scf_cleanup_free_list(cpu);
> +
>  		scftorture_invoke_one(scfp, &rand);
>  		while (cpu_is_offline(cpu) && !torture_must_stop()) {
>  			schedule_timeout_interruptible(HZ / 5);
> @@ -538,6 +567,8 @@ static void scf_torture_cleanup(void)
>  
>  end:
>  	torture_cleanup_end();
> +	for (i = 0; i < nthreads; i++)

This needs to be:

	for (i = 0; i < nr_cpu_ids; i++)

because nthreads can be larger than nr_cpu_ids, and it'll access a
out-of-bound percpu section.

Regards,
Boqun

> +		scf_cleanup_free_list(i);
>  }
>  
>  static int __init scf_torture_init(void)
> -- 
> 2.45.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Zy0m5TBz3Ne55syG%40Boquns-Mac-mini.local.
