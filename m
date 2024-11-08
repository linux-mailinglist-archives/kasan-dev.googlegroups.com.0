Return-Path: <kasan-dev+bncBCKLNNXAXYFBBWGRW64QMGQERZWJ3EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id E338A9C1A96
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 11:32:59 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-37d458087c0sf1831491f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 02:32:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731061977; cv=pass;
        d=google.com; s=arc-20240605;
        b=C05lpTOjWojtIiRLO001AmzZTk5Z/mIknYplie/WZ+0y0jktGv7hle+shq8s1QiBW1
         YA0H0W/L4LvHwDGLRBEylgqJCdZtG2bFhNA1A/FoXbB93kjcsxgOvf3XYz6ipTXqRvRQ
         GUs+Zet/lGm2ekBG1h6Tnqw/x629L4sA+/ojKyhiNvyNLKOZEVIV657MEwzOsI64aaJE
         NJ/mO4kTeeQU+97+cBlybtEKwzBWROzGgKkZqfAqMWxqccOnBXaIB1VpYKfusBrfyLeS
         eDloYrnjVM7MlcekO0g3Mtt29+6ab3XXhTa3Ku3W6Cqs853F9B4qsemR2bVI2pnn5TIu
         rRig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4U8BR+xnx/8YxCb7weM+xx0Okkw29nvf0dDUgozN7BM=;
        fh=ZijSZ7ViyK7viVexEON0OtwrlpENVUOaOon3kncrnCw=;
        b=LHoLtydchaMrGYj4MymmEXExVUZ9ey2XLkdYKRKfTtH/660G2GVc+X+S2qlNleNynb
         CYNdxBk539+dRmlXbBp6gFlJU17BIoPQ1RVvPjUeZrw2gJYyCcHh12gS2KoPCxNywmBz
         j5AxtXRpmO/fS9KvdQzJg0X5BzT/Aenlsbi4Rbac5MkL9xe4+mUazfNoFK7FdgXQsmaA
         knd68Yg+Mo0ktPrWi54atxuKTLRktnwQ+Hyj5W4aMbNvuSbBR6Ta3n9GXlzbdmVC04Zq
         bhpP8a7AFoMYJTE/IsTZMI6UFnDX9jS41j/d/8y3oPnrdwTSwcgkvckY9T53X6ppL28R
         A6Uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=m9sTXmEz;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731061977; x=1731666777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4U8BR+xnx/8YxCb7weM+xx0Okkw29nvf0dDUgozN7BM=;
        b=N7IOGESZ7T73HUs9nPlEtSo2TyzvPLq9KCO9cMPF83wVPL6t72jmk28IH5QKivbeC6
         0pPSsMIL68Iq0AXgTZBytTPuFEToPiTz2cLqS6I6+dalqp278Ey0wI8sQgBUN4dOuea9
         XUJ0E4Ed5tMjzCsFnYjNNQ4o4FFnnOGHF8woE2Frv8HtI3htj+OBQrD4TXLLf6x6YXxB
         KxBNhFusw43McoXXOaqAM5tJ6IxxEXQdWWQ4h9pI/fIgPNMS0viDPCIrLhmMIPB8qEAO
         yds/5a7AwpGgvDhoT/K88XdT4YhXPCsZUeXWtonkDhQw68W4vrnA+NWcHKGafWE3qwta
         x9dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731061977; x=1731666777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4U8BR+xnx/8YxCb7weM+xx0Okkw29nvf0dDUgozN7BM=;
        b=eM5PxDiXEvhjIN4Nv/qtozorUtHyqIM+fjTLd4U2NDn3k9HPdts1G2YMv/1wP38NcA
         zLBO/fBBvcyA8Uz0TMOM2yfTe71BXX9w8qU6+x193+/5lfWP80q25xqAEg1GpPMQsWeq
         DaooEABMYwNFpa5bV0lX2pmR+VnJYJVlMvrMqg4e+++AtT1ZG9/IEv7Nm6/igGawkBh/
         L9CNG/dNwQqgyyx+Hh45mmmxdby2aZQonj5NTPvPeMTfRMulZ4pTqBoD72enKFrK3Yaa
         HLJpU4IYtIRvPBlxhnKXALR4jwg+7sYPeLNVOp/iQF6FU+I/A1zMgtapM+x469bc/zvl
         KjIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWntt1eKAGT8ogihORbMiJn+uatVdMD1hbqLbxqwlYV3xk+cwXu2p5EsGk+DHnRk60+ajKHJg==@lfdr.de
X-Gm-Message-State: AOJu0YzyAcRzUtUU1RcyKy2EhvNAjPYxMVRO+Gc7gvRNvnohTLnXVF/O
	zvGYyu31RvKo0KWqImCmJYmHw1P6PG7awZXw2q7iVPMNyWd0qP8A
X-Google-Smtp-Source: AGHT+IFsmDoiK25CeKf6mFi/3ikIreZUqjab6A3p4ySkJVR523/8Qb5hl5IMpaRLnH+eyhHqqHOBiA==
X-Received: by 2002:a5d:5f8e:0:b0:37d:5251:e5ad with SMTP id ffacd0b85a97d-381f0f40e32mr2642086f8f.2.1731061976781;
        Fri, 08 Nov 2024 02:32:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:a43:b0:42c:b037:5fb1 with SMTP id
 5b1f17b1804b1-432af023c92ls5865785e9.1.-pod-prod-00-eu; Fri, 08 Nov 2024
 02:32:54 -0800 (PST)
X-Received: by 2002:a05:6000:18af:b0:37e:d6b9:a398 with SMTP id ffacd0b85a97d-381f0f58473mr2574595f8f.9.1731061974468;
        Fri, 08 Nov 2024 02:32:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731061974; cv=none;
        d=google.com; s=arc-20240605;
        b=D55SCGU4gQgPGq4pdHcYWxgX4vau7noaWBLk2SX4n5Xknqtxsw0WpQuV8GUWZr9dUH
         /WzdjrQzS0CZLbgjlIQ+p0OoRDRbSv3mls7SYjXI+Uqph0Af5vuWJHdcLwFIpOWYVbzy
         xPMhZYUhJYV2EDMp9S712iwQ2WT+uF2f9oFSJiVsK6Y6ykNzi6e+ln7mpcsIpp1eYNlx
         ko3HR9XzDUB4f03esM2Hnctjc4X6EqoYqjnb2/vuo178KOlTbXiZJpZ3Rr36lg7mLR5+
         /v8wDR5kWH15E/726xK3mWSQfkpr5vAC4aaI+ZgWcHT+c4y1OdVS2Y6YK5uKQ+Dqpct8
         ir8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=J79gOJvhB5tRp7HnYvETBA8AX34Or6W938K5FMMyFqg=;
        fh=0AS25isvAZutvEzy1ieggIlNnJYYsv4cyWh6cyVIuHQ=;
        b=Ic4pmpv5L+Qy5b+iMSypGc4eS9XMxnCKs0NaU5w86jwNSZkhezWsOT2pvx5sKK06DN
         XndGmDWIn0ZRkqqrMfFG2LIVn7bfrb2Ns2+AQkQOHt/1cIDjRQki5dmx9z2pQVTTsigy
         0PBt12x9XyAdgboc0yIsxwHuYECV40hqydv5Ii0C0bHn+nYYESeQhKoQuPR/NPBrDE/N
         /tXIoOLmduCECu08/e1gSM/AyKfFAJbRjVOGzwzf/g5csQzX/Uh5W+XHsJImyYEBjcmq
         ju+Ux7/k4Qy/UbvFQgHVnmEYOc0GiI7dZyquZzU0KBtMBaTIxUlfVsomaR0GI/rxwqEe
         2fcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=m9sTXmEz;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a267d4f7si6254535e9.0.2024.11.08.02.32.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 02:32:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 8 Nov 2024 11:32:52 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, "Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v2 3/3] scftorture: Use a lock-less list to free memory.
Message-ID: <20241108103252.4EVzazwC@linutronix.de>
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
 <20241107111821.3417762-4-bigeasy@linutronix.de>
 <Zy0m5TBz3Ne55syG@Boquns-Mac-mini.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zy0m5TBz3Ne55syG@Boquns-Mac-mini.local>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=m9sTXmEz;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2024-11-07 12:45:25 [-0800], Boqun Feng wrote:
> > @@ -538,6 +567,8 @@ static void scf_torture_cleanup(void)
> >  
> >  end:
> >  	torture_cleanup_end();
> > +	for (i = 0; i < nthreads; i++)
> 
> This needs to be:
> 
> 	for (i = 0; i < nr_cpu_ids; i++)
> 
> because nthreads can be larger than nr_cpu_ids, and it'll access a
> out-of-bound percpu section.

And I though I learned my lesson last time.
Thank you.

> Regards,
> Boqun

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108103252.4EVzazwC%40linutronix.de.
