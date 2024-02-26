Return-Path: <kasan-dev+bncBDXYDPH3S4OBBIUD6OXAMGQEM52LL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E18D4867CA5
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 17:51:47 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-512b412bef6sf65892e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 08:51:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708966307; cv=pass;
        d=google.com; s=arc-20160816;
        b=l7VmmW5eBqDZDQfnoQKYCRs8lp9KwA977W6m93mgkygtdrvp6L7PJR//uNaHS+ALR4
         YwqlfZXVrTwMP6x8QuNs7IuyCZwhfpeY4SpF231Q9oGeobPPjkL4WpNfyXldQR3Jv2Jk
         43cTHWTCY9TSSAlJP7quOzryOi4GTm0rOqsH5C5xKOVkPK7c87GHEZ/QsX0KJ9dB6iSz
         eWC8NwFA05+cV0UsqlHapij5yB51shcgJkRrYVR2Du3/oNfMr3LZpx07V0PEc/38Ue23
         tZPPdZQbuX/TUxxQJZMIHFrP87AUaDqjvuTx3zVp5N9cmt+I/wDJQvU4XbUTQm18+A8R
         LRjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=AtdnG2xZbpN6nCVaIPdWUQ/kuNKY5wNRSOK/PEBiMbA=;
        fh=5tr0MLKHC/RQnmpo4Lj/5XdQOnzAnXsG5Vo0ZLVpERU=;
        b=I0k/IH0cKS/6KG649Fwqdx/N7x8xD4Ca6fZaCvUWtVtRUVVEMm3Pxe+nOcnZMsfATh
         R01m8+dVyx8WJYty8tVyTSL5dEQBbwCwS5UrdFwKMyOMSrGGuD+5anPlSB0mCLTHLsGn
         nPBqOBhJ7zIwDK0VKAk5uZmM1udEPaoqzubqHdP+7z9vc1ufeZPG1uvS9MqXHvOiNvCb
         zXEuY/2nwTqNoJ9PrUS/RRequPs4t3YuiIbi956itlEAdZ4FO7TSgEJyM11F6OMg67UY
         Nq+ojvLEE/gmVBUxO3lYUjndfodd4GdiwiR60+eBkncA7hf2Fq7V/NRpcS4U4/wJSNAS
         CAjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2BWh9ZO2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2BWh9ZO2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708966307; x=1709571107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AtdnG2xZbpN6nCVaIPdWUQ/kuNKY5wNRSOK/PEBiMbA=;
        b=f8LgSG4QNVp0m1Suug7xHhEnRCU5NR9uSTQAFqGsKQA0ZzOCEA9kvLDStjv147aSqa
         Hb6/XMi04M1SyaVrLcUKrSSv6pGL1S1uKasA9M7ZZWMzsiemmhmKRck7ePo4IcRof/Wh
         3TqpPd0U2WoPIswbUuKV9KC8NEhe1n1C3gXGPTyp0zlcrEaEFTG5PRQHC7XrDjtAvn9K
         cceeRnMwf3/qkUXo4UATVBiisow14cfUm74TIBQgFBGovsg0FPs3MKJz4Gv+nXcLdmLP
         G39mGt7nj9SMoVuvNOqnkfUj7DybzQh+LNaHtsbRzX/kXRPOBRfFIhzVJDOL9nolPE1l
         NfpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708966307; x=1709571107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AtdnG2xZbpN6nCVaIPdWUQ/kuNKY5wNRSOK/PEBiMbA=;
        b=fJHcbdpfHoEL4hWTNkkf/A6kGcACw+VwRSrkAuuPrfRmr4GcnPr4rTzGupGRdW7g44
         7t57dY+o9z58VXfVS3duLWD6eL4VWOi5Lui61VsNP+CdQh+FgRMzejBcnL6IUqK8xhbH
         G/ncSlvAlqX9k2PzVn40vWdMtbO0/G/E51i4YaFmcXs4i9pguf0L1QkOuedBQC/RCUNI
         YeYy0hnHH32OogTVxvkkOMoxv9Xm5HX4KS9LMN6gr/peadJdOD0sMRlg30u3mXW26DSL
         daoUQ++wc/TWobmDhWi+3hvP10aTdm5BPP1QRshUuAU6cJ3zD9TmN6TnOfXvKSjm3F7l
         KkMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZPKI9NZeh8xf4fe8FjVtTEg8gJcS8n/zBbNm1EuqPbMHhRjfjfiahhgh9V3v/4ehZ5iYo2WweWd9Yuow7osMkHHE0Evpznw==
X-Gm-Message-State: AOJu0YyjwVlvqIGjnyWDM91TDvPFQ0NnX5hZXj/jpOxk+Mlpq7XnufPP
	fH39eFj7b+2cJorpI3ra3Mdn7wJZiK7fi2E6LGaeK95h1R55Yn2r
X-Google-Smtp-Source: AGHT+IE+GNSS0WzxvOTcUYHabtZLLdJqEzBaIVPfa23+2pj9rZvrZBZTSBan/dTF90s6210u75ooRw==
X-Received: by 2002:a05:6512:159f:b0:512:fd94:2407 with SMTP id bp31-20020a056512159f00b00512fd942407mr173699lfb.0.1708966306784;
        Mon, 26 Feb 2024 08:51:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a615:0:b0:2d2:4480:ddf7 with SMTP id v21-20020a2ea615000000b002d24480ddf7ls311074ljp.1.-pod-prod-07-eu;
 Mon, 26 Feb 2024 08:51:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU/pahWJ2VklT7oQGsnbn7ZvoTXDou9ktXIalWFdqrWSUbYdQp1u9ezQ0jomNMYcHnOfwOYDXer+4m2vyr3MNZD5TZQ7ef1BetIaA==
X-Received: by 2002:a2e:9402:0:b0:2d2:4ccb:747e with SMTP id i2-20020a2e9402000000b002d24ccb747emr4014515ljh.17.1708966304717;
        Mon, 26 Feb 2024 08:51:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708966304; cv=none;
        d=google.com; s=arc-20160816;
        b=ucTkouiCOagsW2o4Gqt4Rkk/JqLEgsOFMOFBAHMjsXrHRQ7WYe5L5Wa0BaxUx4B6xZ
         n+Z/OrZhqDikBdypJR4Auye713zH8zwnj6NIKJJuQ7TnxWUt5PUExX2CVeVLD2k5Tnml
         zJ8kn0F6Zrfo7+e9AXCm2GX5ANUYUkj8ouJ9wlHhPsyBVUVOtH6TCtw7DhJE++mdlagf
         JZO7j3hysVlWiekhio9DrKJpLnbdlvnyuXTOs/a8DRB21kkI8hauCbA3BFtqkMkMkP4V
         6KD0zDEF/HzB342262olIQb6sa3yy3Zj283rYpDswXsSd9eHN33fvhHokFDfwxxCvtz7
         +nvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=uJZhnt5DTMh+MpsqVvPBL3KYGUK68E8u5IzFbAjaEiM=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=WfhZGLdSlWjskCgg3SsKO5fg85MyOXUIn3rW8o3UkLKj5S3U6mme96JsCatm1L5p/W
         96PtOr6F88jo9vaLkCaQANmisrYyayelxOY1On9ze6osxXMcSTCEXh3uIZZXoai1Oh9v
         YLJwTnRPYgYU5VRGeU5DbdzGD/v4cPV8vH6ezJNkJVdcrNEqGGOVNvCPqg0Q1LwgUxsi
         f81I4n9uQ+DUsR117k2vKc9luPuqIJ3r+QsOYQ+hySScIwEajcvWD8crIIPKV8Cr9Sze
         p3wBuX+zR5rJD7R+pBTDGcefyKGylHum/MlOO1FT6BBMe3CEyA6wAz7lSwseAH8KT3se
         S0Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2BWh9ZO2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2BWh9ZO2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id i16-20020a2e8650000000b002d28d13e6a3si144513ljj.5.2024.02.26.08.51.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 08:51:44 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id BE41D1FB5F;
	Mon, 26 Feb 2024 16:51:43 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1A77513A58;
	Mon, 26 Feb 2024 16:51:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id MgflBZ/B3GVLFgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 16:51:43 +0000
Message-ID: <a5a5d0ec-b04e-4cb1-9ac8-9aac00badc0e@suse.cz>
Date: Mon, 26 Feb 2024 17:51:42 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 08/36] mm: introduce __GFP_NO_OBJ_EXT flag to
 selectively prevent slabobj_ext creation
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-9-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-9-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -1.14
X-Spamd-Result: default: False [-1.14 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_GT_50(0.00)[74];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-1.35)[90.46%];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2BWh9ZO2;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2BWh9ZO2;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
> when allocating slabobj_ext on a slab.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a5a5d0ec-b04e-4cb1-9ac8-9aac00badc0e%40suse.cz.
