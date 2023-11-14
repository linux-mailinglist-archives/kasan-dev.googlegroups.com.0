Return-Path: <kasan-dev+bncBCKMR55PYIGBBFFPZWVAMGQEKJZDHEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F3B87EAEB6
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:18:46 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c5032ab59esf50798191fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 03:18:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699960726; cv=pass;
        d=google.com; s=arc-20160816;
        b=NlPMF99MSntreI/FMawqp3A/35erTjZ7W6+HZKHcRhkulGghMZF+iSt3ngvsI5W2Ps
         sF6dfedgIyh9+am+YEpXIxzLABMUaQmyo16SBzh3XwO6kUHDgWWbZ8Ogwmrb6+K5PxqO
         3LAVqkUNLT5ZbKxCdB7+vCbWaOKrM8D+tQKTJRIWiovlH77DxcrKV1dAjDDyqDK9bD6O
         58lS4yVFAuKoXWL6mcSXyCpNQxi6inbvmVxa5BI5bPio87ZdFsqc3p+FdjEPkQ/5d7Ou
         GlNclwRsb60/jwbzVMF+3htV83l4FHuuxDV+dIPTWFsxiulINxmXjhbAmwoAGrhAu7yJ
         4dyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=alL9+hdxNj/C+TPmVfgrBKVA/T+WVkCbmqBY9oH1/Lc=;
        fh=nYtaDO5H8e3I+e0Fs1cFZXNS6k7fh10G/jAvTGFgWoA=;
        b=bhOPC0TSYBPiW9ZVHU6sydM9pKFIbkvYTAD9NyoNxqFhiOMtVg4YjhM8sITju33LsW
         X91jNM9irCON3RS4umjYDdbVtgHLCcdPYojDHiMSnV8ed8tgrYFbpQJOZqPn+bIqP6ea
         MeCdfV6OubV6nQvPMKaKBaxHtpVq7G7efVsWfvdzh2dw2COI3R3fgT892A3C4FQvBqnX
         QUgHRe8ULzMIMLQzpdiYVgdEigp64LOoc9QkCozpciN0zDdD3WmF1Am7G4FSswoSnF+M
         GNV4+YdLdVFhktQ5mpTwORBo4AecT1oY6jjY3k6qGETC0YtnFwCZCQu2GVJAyUQEUSAM
         Y/nA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=W7QLIXbC;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699960726; x=1700565526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=alL9+hdxNj/C+TPmVfgrBKVA/T+WVkCbmqBY9oH1/Lc=;
        b=DkponADyQZiwkmU+EYCTyKcQdu8i5yNK4JlYzMhG3xPfjyKVW9SRuCWgviSrBzBUHj
         R7LvUZcBS8Yz6YXxrzq7K0z4N7mDgdlXGrWjPBRdIKBhs7QUEjUTT3CswCDaDNDu0W7O
         XsQmYyUnB7A5raKsLGtiVZLrmrjJ/Fv2kZjD3X4/9A7yAV45hBMegQA+lvTOPFAF+Ike
         HdByy6DmNEiUGT8bXxJc2R2JynRt0UdtoTn9idvarT0NJ9PJVWleD4teopDewLaBqCzW
         09v2kpuBrF3dW3cFqwUaIL7nJPXxauxukMTU8nNUxaW4G9/gttfvTtulc6fnlqASm3tk
         SHUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699960726; x=1700565526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=alL9+hdxNj/C+TPmVfgrBKVA/T+WVkCbmqBY9oH1/Lc=;
        b=FXZSwNyln8fdW1I+zyy0AE0GoNuBBNS0jbvZ2juIE6ryiBH1Q6wJjvYMMDF8/CLqce
         MWLPJa9qwzKbc8VBYFkHa/SbYK+DwkyOBPnYvQpOldXrDvm+G3sNkr4eQdcfu8SsnfE1
         EobKayW8UoCwiWgK5EBF5HJLiQ2jdTzE8g1oOtYUAWVK9kslt43qVXwQ28pSYsOVeuGO
         9Io24PKTFVTSCLIGIlPMY0gq42jRuqateoZuV6nGYPoZKui/wN/EcCPxsv+RKmFbvq8g
         HMNktfWV0Pogf7yOjiT/P2YSRFcj+qh4XHEgToM20CWcv1F1iylEi9A0qFlVt9hnQSDm
         X1WA==
X-Gm-Message-State: AOJu0YwQsbFjP/ObQMaUiTYE7bqwM2cp9cQv9Gx4e86unWMmxvc8hrEM
	razKTNxIg6CTs8UTxR0mGoE=
X-Google-Smtp-Source: AGHT+IHAic+hPwEz3hJZP8aFkiLOgsiLMEpyab3EyXtD62KeuS8b8THOPFzg4yGD6QprZtIozDKi7A==
X-Received: by 2002:a2e:9cd1:0:b0:2c8:3ab2:ecae with SMTP id g17-20020a2e9cd1000000b002c83ab2ecaemr1756148ljj.42.1699960724849;
        Tue, 14 Nov 2023 03:18:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b810:0:b0:2c5:356:6429 with SMTP id u16-20020a2eb810000000b002c503566429ls96047ljo.0.-pod-prod-01-eu;
 Tue, 14 Nov 2023 03:18:42 -0800 (PST)
X-Received: by 2002:a2e:a545:0:b0:2c8:34e7:b8ea with SMTP id e5-20020a2ea545000000b002c834e7b8eamr1604228ljn.53.1699960722435;
        Tue, 14 Nov 2023 03:18:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699960722; cv=none;
        d=google.com; s=arc-20160816;
        b=RfAXTwuVfMotpxdnQ8oBOQkHlrNfYVPrOLIw7Tg4MXoqpvoV6Oe9DFgnO6kd0ekEQv
         mQSDRPiMkM5A641YwgykxQVfnrgYaayf2760UIgIToLJhCddDyco7nEdhYbbPPLBKl/o
         llJ4sd+zoYJE8EbYy7GnNPk3sz391fJZhpnjXTrUFnor+mkDuurUHf9JPDgWxTOzNhBL
         rbxC0c7GUxU2gHzXGjv7lBsfkCVM1qxG03OySiFYMPtZAKL2Xbq6q13gyDeLOIaT6wMu
         hiHdsB08My/b+tJMNWPMzrub1z5FQUTLi2oSPRGR9eoy7NWgGnfpcX+hxhZ1RAKGrk4G
         GuNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=siI4v49ul10sLUO0tQMqvHE05UpMxGy63FAFDTFOHMw=;
        fh=nYtaDO5H8e3I+e0Fs1cFZXNS6k7fh10G/jAvTGFgWoA=;
        b=fo27PAGD6ie6snwKRTNN2fBo37QWOPbvQnBCskYpTNOqI+5Bg9KoHtawGdDbsFD4Al
         Go6VDW3Z5TtQID3C7QXbCHZ9dJegzbCZMLQcTXmF9ggnR3lVZZOSQHb8a1RNu4W8bJEv
         w8YAESDuHqelh4TKtuH1beYZ+JJ2n5rmcq+Re3Vavm7PJwYpD1tBo44x+vqnUGRLha+o
         y1579qoDCxfKyCPpx2Cfduwjlxtf4DA2w9gighh8Juzm6pkWNrbOiN5qmzhtvZ5Giewc
         aZGN+XwDRAxhja0vlidqsn1+QLKeZ+L3WJIv6mUqoNlp16j3IxjbtT1rJDev1CWMZR6w
         qjRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=W7QLIXbC;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id k5-20020a05651c0a0500b002c820f71e0bsi279243ljq.5.2023.11.14.03.18.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 03:18:42 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CC6E621898;
	Tue, 14 Nov 2023 11:18:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A6B2013460;
	Tue, 14 Nov 2023 11:18:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id V97lJZFXU2WyRgAAMHmgww
	(envelope-from <mhocko@suse.com>); Tue, 14 Nov 2023 11:18:41 +0000
Date: Tue, 14 Nov 2023 12:18:40 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/20] remove the SLAB allocator
Message-ID: <ZVNXkENBUCipBuCg@tiehlicka>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
X-Spam-Level: 
X-Spam-Score: -3.43
X-Spamd-Result: default: False [-3.43 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 BAYES_HAM(-1.33)[90.32%];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,chromium.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=W7QLIXbC;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 13-11-23 20:13:41, Vlastimil Babka wrote:
> The SLAB allocator has been deprecated since 6.5 and nobody has objected
> so far. As we agreed at LSF/MM, we should wait with the removal until
> the next LTS kernel is released. AFAIK that version hasn't been
> announced yet, but assuming it would be 6.7, we can aim for 6.8 and
> start exposing the removal to linux-next during the 6.7 cycle.

Makes sense to me.
[...]
>  27 files changed, 784 insertions(+), 5122 deletions(-)

This is just too much of a maintenance burden to have a comfort of
multiple low level allocators. So it is good to see it go. Not that I
would have anything against SLAB allocator as such but if we need to
choose SLUB seems like a better choice.

Thanks for all the work!
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZVNXkENBUCipBuCg%40tiehlicka.
