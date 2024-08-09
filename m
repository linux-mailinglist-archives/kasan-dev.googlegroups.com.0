Return-Path: <kasan-dev+bncBCIJL6NQQ4CRBJ573G2QMGQEZZWDPGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F26A94D649
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 20:27:58 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ef1ba2a5e6sf24448841fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 11:27:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723228072; cv=pass;
        d=google.com; s=arc-20160816;
        b=FMlN3cSPaVUhF97ObRdWovCmKJzWVcnbOHyUoq48vFyQPfj9riAN/0yhO+USAUAGwI
         HC3B+kMQAUxoaA7n9g+Tz0f1HGvjUrxMTmYeXvLSWfhRax7pHHR5EtxG4l35zhwsIUOt
         +SiIGUqkBKrg5E04mUy3ZMv7xCGubtQ/Uhqm7g9bV8pvwuKIzNS1kJThGU1PtOF40IFA
         RFeefAzIiVoet9UWeFky3JlxyOPlG+Qq1JXsYP+yF+PnJm4II7nId9MqL55DMVrm/3A4
         TUvnOD+fsu0hB0eRbXFymD7Fd8lbtvlnHA2YEiivghleevDy9/9xPYoHh7mxUw3iSL7+
         WccQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=oGkmpUIoEhHoj/ks0xo6KGlv2+AOGJG9XBSRy+3mS1k=;
        fh=7mmlfXIbDvno7PfgAezJOj+4fXvUETwOi/meMeWDDOA=;
        b=XFTMylusHxTQQKqQdnSg0LOMj/F98nMnsoUFfED5frPpcGmINROMVgUTR3ZPRvJigA
         XOvM1VMOh0wyny1QXp+tMOOqO9MpDCthwpm3wbBRYeupRgk9RVmgLJeCEgH6OxgWPv5g
         87TT1omoBjV5/JYHH++CbQnH11h6DNQqD2ff8+UfPC9A4mM2Gai6emcj1x8l//BWcZgI
         IAvKajdlrLTKYPHPfZxVJ5M7EK656nUm0ftIL04+YAdG6U6mTbjX3maB8CwW7qwmxhzv
         y5PXmVXZk9n+RLWxF3RnALWInas3UQzYyRyxwnUIuX6NSyDpNgFOvlhYOaQoSvuxM9iT
         aZcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Po7AcCmx;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Po7AcCmx;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of dsterba@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=dsterba@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723228072; x=1723832872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oGkmpUIoEhHoj/ks0xo6KGlv2+AOGJG9XBSRy+3mS1k=;
        b=B4Pa94fJyYnbhefr59g9buyo6butg0bs0TA8ncTs36CY2bcgdWqW+8cYXTn9LwgE4k
         mMsuf2Y8Y06Ie7kV+QnTyz/TpWLuWjyHs8xj03bj89MrfmqRwYKo3lWzL6o4zmKzWBI9
         F+ELuH+TZFZLdx/lubzyFTMdzYN2A4M0qfetkhZaHNv2hvNSL+9fDKAQBfBwoSHt1t4B
         7ROJ9B5GZF22/k7YLN8lALq2kDGtHsFzViBo6NJhDeqHPYC6yccEc2IdhLn/9sfclHRj
         545KJovdzJQWhbQBOB1HOkv8NIk+gA3xcAlIFzmkHSH2o477561anCOFEZJ0iHeK8CSg
         1cUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723228072; x=1723832872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oGkmpUIoEhHoj/ks0xo6KGlv2+AOGJG9XBSRy+3mS1k=;
        b=BazmzxjFiCzkzix/zhfM3Lm4ilh/1YjypjUhAfC6Yfn0xiGUlb2PEfE+McQwBr2+71
         fDT4fiEw9KnFLgdcwkaFBN18WfNYJw9ZCi/tY105dEldoZsse3CQjqV9O2jxdgz/nHYx
         /0Eg99ZJ/QRiMvhuXIm4t6ssEGPpxizthKj9tFFY73uiZNhCMH5PPgPZbvviICnMOOWh
         HTPD5ahmPUp03vMRgmPuPpsfjrLGYaero9T47oo2vqU6sMDW5k9h0oJpenPigmA8hPst
         +xa8w8XBuAcqNdT50nMTyNfPg8t0nS34W35mORHrR3oioDq2NeDNjX1rjylGKI+5QO+j
         Q+gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCFuJG/TSPYja0GeH3djr/MCaC4H/O00ps3zcruq1zTUY70SwEwSDekPb77gItcm7mvQFL87QzMJaL8x5HgM7ClXUklRuOwg==
X-Gm-Message-State: AOJu0YxcJogUzpc17zEAyUOKRvEeHqXLuZgYRn5+nl2NfA/6GMySkzb2
	iKC240JHSgVU5i5KG6PEHcJ72wcO9+MZJZvQtF0NONrQk4ngO/yY
X-Google-Smtp-Source: AGHT+IGzrJAlrkhyniQ232WMbl8DtHviDrGBrqc5SLDgiluMea2xfr1twsqXfb86M1eNFkWZRj8e9A==
X-Received: by 2002:a05:6512:68c:b0:52c:c032:538d with SMTP id 2adb3069b0e04-530ee989b19mr1706207e87.27.1723228071336;
        Fri, 09 Aug 2024 11:27:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ba3:b0:52f:c300:1e1f with SMTP id
 2adb3069b0e04-530e3a0bdbbls247145e87.1.-pod-prod-02-eu; Fri, 09 Aug 2024
 11:27:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3sIrb046uY4I/gRps/c0YfIZzN4N5iZ4dRv98ayaK5t/ku2B/kcYQYddEpqYJ4ZZRcGzNAevcoz9umpGmop3LFh+a2KDlhT8upg==
X-Received: by 2002:a05:6512:3b1e:b0:530:ea60:7e07 with SMTP id 2adb3069b0e04-530eea20eebmr1872882e87.58.1723228069052;
        Fri, 09 Aug 2024 11:27:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723228069; cv=none;
        d=google.com; s=arc-20160816;
        b=Bf2rUSIVs57FGpod15Y/4OKGd0d8C10enYeSBloAi+NTZEGg3nxsKMGhCT5cJi0yge
         A4s3+HQHYib2RSIIeWKBuoig0rTzHzjICeB+k/x0Cmgw3ZLtfDCc6kaQlWe7tqL38AIn
         +n/cCPYP+PFM/NSDq/8x7R+HkNuIA9hcpeDYDO34igbjTHbdCnVBMzlWOwJlOBUsRmUO
         P+lujl4AwZN12iYHDgw6lDF5QZ2TsFqapdgt/iNlVdFHEWi4wq9NnnfnMUKtL0MIm548
         IwmoXMDuhhpxiNw+KKP288P95+uKgitgMHRrQGjJRiVY6PytzFnRq4O3/2MiDmmVmywl
         xH9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature:dkim-signature:dkim-signature;
        bh=rySDgwHwzk4soBkVhT5EA19C8VPh9xFHysLEK1LhtqQ=;
        fh=A8Xe92PxLTaBHXNVmuxD1aYlUXSc9iOX/Em7ZbsKVDM=;
        b=UzNvgwPPPGMKOQkjbOa1TnFXJyE0X6aSFFEYK2TT+LksfZn2epL1wos2RR2PB7IcCq
         g6C1m6QYBb0coWO8q1cTWLX/Y+aCeYjU6+9s8Vf1Ne8ION72SVw3Ct/eYqf/SaSfRy+9
         CkayVR132wdE3i4Oi2OyVzsF4Xmh57MbJRZp8kimvnGgE2eJn+C1VpJ85iOb3l8Dg6Jt
         qVPze4W4DylDZ2yK5XkYY2/TQXDujZkdSpov9gViWN8c/fAZBjEo1J9n/cF0I04kv9gB
         xiuifmlsiOEpl6B/dgI8vVMsYOUzmBOWG9S2zs9ZticVn4uNhmpMNbPJ/0e5DA1m+7+q
         Rz0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Po7AcCmx;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Po7AcCmx;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of dsterba@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=dsterba@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200f09589si82e87.11.2024.08.09.11.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 11:27:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dsterba@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3170D21FAF;
	Fri,  9 Aug 2024 18:27:48 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 07D7B1398D;
	Fri,  9 Aug 2024 18:27:48 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tr2yAaRftmayUwAAD6G6ig
	(envelope-from <dsterba@suse.cz>); Fri, 09 Aug 2024 18:27:48 +0000
Date: Fri, 9 Aug 2024 20:27:46 +0200
From: David Sterba <dsterba@suse.cz>
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, David Sterba <dsterba@suse.cz>,
	syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Subject: Re: [PATCH v8 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Message-ID: <20240809182746.GB25962@twin.jikos.cz>
Reply-To: dsterba@suse.cz
References: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
User-Agent: Mutt/1.5.23.1-rc1 (2014-03-12)
X-Spam-Level: 
X-Spamd-Result: default: False [-2.50 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	HAS_REPLYTO(0.30)[dsterba@suse.cz];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	REPLYTO_ADDR_EQ_FROM(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[263726e59eab6b442723];
	FREEMAIL_CC(0.00)[gmail.com,google.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,suse.cz,linux.dev,googlegroups.com,vger.kernel.org,kvack.org,syzkaller.appspotmail.com];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_HAS_DN(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com]
X-Spam-Flag: NO
X-Spam-Score: -2.50
X-Original-Sender: dsterba@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Po7AcCmx;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Po7AcCmx;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of dsterba@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=dsterba@suse.cz
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

On Fri, Aug 09, 2024 at 05:36:54PM +0200, Jann Horn wrote:
> Changes in v8:
> - in patch 2/2:
>   - move rcu_barrier() out of locked region (vbabka)
>   - rearrange code in slab_free_after_rcu_debug (vbabka)
> - Link to v7: https://lore.kernel.org/r/20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com
> 
> Changes in v7:
> - in patch 2/2:
>   - clarify kconfig comment (Marco)
>   - fix memory leak (vbabka and dsterba)

FWIW, I've retested v7 and got no OOM (caused by the leak), on KASAN,
KFENCE and other debugging options enabled.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240809182746.GB25962%40twin.jikos.cz.
