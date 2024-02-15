Return-Path: <kasan-dev+bncBCS2NBWRUIFBBP6IXKXAMGQEM5TKOFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id AFFBD857204
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:54:40 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5119f6dca82sf1373344e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:54:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708041280; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQ380AarmAKBoiLaUvt1/+yBsk8LftMBkjJ6V0+2TAuI6zu2gsmo1HIgpeXTdLB50x
         OBhC8XEg7MkoOjXJVnvaRnfF+lvFgmJ1/Hd9uidw1mBnWpI9OVTreR+8issiJiURef94
         qoNPZwwIP3PbwfHAeHc2rQM675Q76i1EblsbIizvEX00JL4z0rFustsl/Vj3XeRgfC96
         pAYHsO0g2OuvbdosSH5ryjcK9V5t/iktYXsw5tFHuO9ccs7Msvm8kSXrq3h5xovRxMgc
         05NEGeWvXqVrKVWFIx5JCqmt1dx9WDTAjFw0Z5rVgm+roXLaDp3krr6k3hwBxInUwlBy
         2KCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Qw1c73Ea1FhZMC+WxquM01I4/kA8TJwy4i/LcZo2suY=;
        fh=trrYNfdDivFsYzIL6NxkAbfrp2yLQWl4JtXEL51zq/Y=;
        b=F0hRGV0zXQAtJDKEH3LQmOI2gtCiKLJR2QOy0dtQjDkREjUtJhkBvYqJDdrSr8S8F/
         c28y8FsJVw09D5/Zto9ujl3s5lsOyaBgL5WUOFdsLmbaNXE3Ftf1CYTbaxZ1SmDiD+Ap
         jCJ3z6L10iqD/PlZOcrw0JBRkUnBOjxwxWGmtgSuKncHTvvsq/w2TySPfRJGRXUA8q+w
         1LW/bRsujEVkEM+DJ8WT8ugYCtbfnisuSY+cFZD5Chi3u2EnGbTYJ3DVKUPxVD1/JggK
         vL3FPK6XqvT3g4V0lwUzH91MP4DViAAslQtwbM+rh0Pbo9X6zTw3EVK3U4M/A4LlP14V
         4rJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=V1agdiFf;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.174 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708041280; x=1708646080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Qw1c73Ea1FhZMC+WxquM01I4/kA8TJwy4i/LcZo2suY=;
        b=IEYxik9JUkdJ7yVTwKrwBZhoy1ECGJmyb4zx3FaPaRIYsyOTgPNEYhFbWQB5znTeuK
         3gScKGfK1RTgmy7G78EERq0WZDFF5bnFz88hoWEzU8ez/W3dwM44m4oy0nxsP1NV8UUW
         PTwJLfjLobPMYQji+o5d/JV7eIS1WZD2VnhqEhBG4YxyFaFHUJ1pn0ZREpwVgsWHShbD
         E5SLXJ+9qu96jFPofgLaqtY6dYrj1DL6mbhKe37B56vM9TjSKtEkhm6GxuFVRES8N8Tq
         8ckogyBpotF7c3gy6Lr5DF/zusldPRgtFSy5RNY/39jajBxhJfdzUmXyfUZMi/SvjnGz
         lV+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708041280; x=1708646080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Qw1c73Ea1FhZMC+WxquM01I4/kA8TJwy4i/LcZo2suY=;
        b=vsGzW9Q6hMhBcgfxQYCPviHsRruZ+aD1cFWW0X3wx/8rAUW9WdLzToorcIo953YYBo
         VF5hMxBhj8xLyS9s68ak3riRt6OgAy8RWW+Q6HAnwhcFwWrzmzDUoj8SmM/1Ywu0++JW
         CMP8N4WRJHgjuEbEtv+um/Qdsy5ijsS6X4Zau8Hc/f3TcUJYd8yR5AkCPiOrPtXxEsUv
         jrDDscuq2xBGU/SWjbktdudyh5+4oL8vELP2HIfqh+JakMQIJcs/WErwpf1FEg0tPvmx
         YPZsYOXz8RoX/Lria4wg9VIxRhDN+HiHE7tDjfBdSiKtalP551B+QyZ9ad/NcinNlWMq
         sOcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5GNAySVbPaPWpQBs6uUQDgd06axYUQ00hTv/QuMWAoPeupOVKless0mEfpZViUQvRbNokR7ctzgj80ZWXr/miNLhez1KX3Q==
X-Gm-Message-State: AOJu0Yx2YiXBnt2Fa3zYBUeAtF1EPfq3ztEgoYiMRBEv+noU3BXl/rCa
	k8VzA+SfgnTkoPiApi/ndF+vDZGK4nBqMqHxYiKchn81yZu/OggS
X-Google-Smtp-Source: AGHT+IEvEzBNczthTky2VBQPXsr3v8YV/1rCh7gswg0sif1K71ME6kaNNq3RNoh67I9ukUgFhKZWcg==
X-Received: by 2002:a19:6912:0:b0:511:a578:b0ec with SMTP id e18-20020a196912000000b00511a578b0ecmr2332196lfc.49.1708041279717;
        Thu, 15 Feb 2024 15:54:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d01:b0:511:528a:c0d6 with SMTP id
 d1-20020a0565123d0100b00511528ac0d6ls156420lfv.0.-pod-prod-09-eu; Thu, 15 Feb
 2024 15:54:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGKcDx8znjthW0bP8wrk/eBK+Ns3NQWIEEwIQ31+EVinGys3o4qVsQftN89z8u5ioEycRShFBz+gwFBeHZ0JBTjI9zvl4C0idJAw==
X-Received: by 2002:ac2:518e:0:b0:511:6764:a8c7 with SMTP id u14-20020ac2518e000000b005116764a8c7mr2540617lfi.10.1708041277676;
        Thu, 15 Feb 2024 15:54:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708041277; cv=none;
        d=google.com; s=arc-20160816;
        b=Tf3kVgT/u9qf2KaJPEQf2lJOmznmKSmJAAa0I6t6k+JM8eHLrrRnusu2x0e/ifGIXa
         BFIE9HADZ8PwQhRGAXc3ue5WC+sulZU5D/Od3ZdHJX7Y2RMApTKCayiGg3hDN2Kl+oSq
         vZAZWBcD1YUtSBAKS6Sa6ZZAJoE2ML7yIwNuNQmD3u4EPGBPgRmrpEt7aU7alNOR4qG7
         1VbTakcD3m+08pCbSNEAdVMpUleDAMDdn/CASkXqWZ4DPVhIAWOWwZppQaeYTvZSRP9Y
         KE3r7eO+gBCxWSCLTtlcGSbntJ3nWkjrV3T1yvL2hW9BBgpDt2a2WCKfPfZhOZQAgYQK
         Wixw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=K2uij+2SL3ce4+254m7l2JMunInmvxqqhYhnbhOg6QE=;
        fh=ri16QTP/cS5ah95n99p/phw60I7/ZPEoxjAJjLXDar0=;
        b=D/NFXnqpVMB0cb0sIjfcd1U5nv5pttucqURpr/jJk7pfR2SKbAyFIuyt+vi52ohxxX
         aLk/qaJGXEnlusnTgTTTN02m3TMgU2yHP25Tbq0J0jTRrnnEPoBORiCmlWUEbrZqfW9L
         FPsbV6mCCK3lPH8H0G4BGWCZGqiVxTykUcun+KU1qqUHsZVCetUO9JvJl/fK1W2Hlbto
         cHjKcLCICelGmWbT1r8KKQEARmYpnjKcdqaveRgPOOjECsYGnFb1cnIGFLtzf9ANgdqo
         Tk6LwbKNAmO+N9y+iVlCOMSbhVjkxeKpd3kPnr9ecuhNVuQwRqTmR3Mji4Wszrn8U89Y
         zJDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=V1agdiFf;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.174 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-174.mta0.migadu.com (out-174.mta0.migadu.com. [91.218.175.174])
        by gmr-mx.google.com with ESMTPS id y21-20020a199155000000b00511503f9ab5si167334lfj.13.2024.02.15.15.54.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 15:54:37 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.174 as permitted sender) client-ip=91.218.175.174;
Date: Thu, 15 Feb 2024 18:54:25 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Dave Hansen <dave.hansen@intel.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <6mjunla45lkwqvkq7jegiw5lfmufg4y53zegevep3iwvy77xub@2nfmbeo6tvz2>
References: <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <38e34171-e116-46ee-8e2b-de7cc96d265e@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <38e34171-e116-46ee-8e2b-de7cc96d265e@intel.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=V1agdiFf;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.174 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 03:19:33PM -0800, Dave Hansen wrote:
> On 2/15/24 15:07, Steven Rostedt wrote:
> > Just adding the patches increases the size by 5k. But the rest shows an
> > increase of 259k, and you are worried about 4k (and possibly less?)???
> 
> Doesn't the new page_ext thingy add a pointer per 'struct page', or
> ~0.2% of RAM, or ~32MB on a 16GB laptop?  I, too, am confused why 4k is
> even remotely an issue.

page_ext adds a separate per-page array; it itself does not add a
pointer to strugt page, it's an array lookup that uses the page pfn.

We do add a pointer to page_ext, and that's (for now) unavoidable
overhead - but we'll be looking at referencing code tags by index, and
if that works out we'll be able to kill the page_ext dependency and just
store the alloc tag index in page bits.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6mjunla45lkwqvkq7jegiw5lfmufg4y53zegevep3iwvy77xub%402nfmbeo6tvz2.
