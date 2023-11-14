Return-Path: <kasan-dev+bncBCKMR55PYIGBBUVNZWVAMGQE3KTIY5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E42F7EAEAF
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:15:32 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5090b916b7fsf5867668e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 03:15:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699960531; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0rmKJoCQk4OPPqtGbz6BoSDdqi32OTDd239jZq9HWqXGhXtO6n38Q9RADyol5q2ov
         PmjXtXmtVIFaeumb7qt2GBIDk/3n2GNUz8R9JJOIAIN3l2rcmIbM9kbfLmC20q49M6Hr
         3wadJo6rGEjpaWRk794YhIXvWv+0MQdmjIn1VBxWTzW0E80aYsdw3jnsg3hEkZPYPX1t
         adAnx32Mn6ZQayAGTP2LoSgtN78zVpc4Yp+4Qk+m08A0Ao3+LEj//lhmpBzkpp0aAlSF
         EGVBKbg1E6NADdYt4EJpx/4rGm63S/dUIG1aJelCAtN4pe69awxDK2I/wbsRXwOxFx05
         w/Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oDLy2zB9crjd9beEt/AQCMyBitrZ8szLtGtv8E9m1C8=;
        fh=nYtaDO5H8e3I+e0Fs1cFZXNS6k7fh10G/jAvTGFgWoA=;
        b=ucfynteKzKEblHjix9noERh2IMAJbsmj9/eTHocllZOAfsBtlTtZv+MZ8neGRaAHWj
         rWOX6fX6hI7LOOSYMjSwLXrxZFmWaG0qxEzHdPjDS7iAoZZiTE7e78JpJx139+eJ/H7j
         +QLDvVKXcyTppi8nNyi8g75TUuzqDH8dlegjrzdC71u4sd4DKlLtdIW/0bvixj1YXFhu
         X7EOKRtyiy9nkkytQh4MmjwxxJYaY5n1gAf+LoiR4LBA5AU/sIwzif0vPheGO3oGW3TF
         xSO8TOJSshYKP5vtH03F4p1Q9btpepo26TGHKzUhZgKoRtLl3dUH9UY1mV/ehQMs3eF5
         QXug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=bKiv6KUs;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699960531; x=1700565331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oDLy2zB9crjd9beEt/AQCMyBitrZ8szLtGtv8E9m1C8=;
        b=DxvnOqfpu+MwB9bSuraH5hxQPQCq1x4A/QbqTZrf614wr91AgZ1XVJJX/4qQSHmiGl
         GPaXAyQBkwjnkvk8KTqcQmzTDm49kOERcBjQY8/yG5ra/8FV2gklc3ZXAaufXlJ0wkue
         4VXMR3TX/iNQ6HdikXbBPFeJkEpeYYVh+iP6/+9enrYOeRg7qzF7RUxDP41EBc5r/Ffk
         GuhXlCrKXt04PEnPEJ3Iriyr9iuE6adfGfM8FKbtbYcy/L6kVsxAw5yQkPXY7BRyMDsd
         1qn+2VFg9xBtBdusW3lAjN+qqWgju9qfjEOlC6DLsEx642e1kEwyjbZOYzhmjyDAD+V5
         ljUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699960531; x=1700565331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oDLy2zB9crjd9beEt/AQCMyBitrZ8szLtGtv8E9m1C8=;
        b=eKkP3vpQUPk7p+b+ciL8KtzBcj6GwlspcEp4Yxe0B3W/GVh7uE5B/LMZXhI6gVq8kc
         EjVXfKNqeWpmH504H3H5AijB78YQzRD6r/i9OwkLxNYdsvtyNADuJdq/YQ3SyOuKZFzh
         3F3vfcd/Kl96eCTgQ3VgZ1YMtfw1OuLa/ZKqgfmu3bQ71VHos0b0JPufmPvGP6iJSGfk
         kdM3FPgqddpGlU1c0sREBZL3AlNJZzVK5rYhRy8buLfRlbmfB/ynyEY2RiER8Wl8oJFv
         YbkaXOADdhB8JMxGG1jKwMHbH4iB4dZR0akqEUYJwDxrOWXIXUZD3opwFFELWG+4aPTA
         +0RA==
X-Gm-Message-State: AOJu0Yyb6Q0oyN5F5LN91pJynSgKdqmlHmJH7d3zfI2UEhnjbbq02pik
	GgvBIfIPPp+bQVWMrZARtGs=
X-Google-Smtp-Source: AGHT+IGE654Qlk1NTmIHwigydGRk8r+g8T94ZhSaSp0/5EW44R99wMpYBLQLVO2S2EQZ4/Qaj1hqeg==
X-Received: by 2002:ac2:5e87:0:b0:509:faf1:ab74 with SMTP id b7-20020ac25e87000000b00509faf1ab74mr6114543lfq.58.1699960530867;
        Tue, 14 Nov 2023 03:15:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40b:b0:53f:9578:1b14 with SMTP id
 q11-20020a056402040b00b0053f95781b14ls232170edv.0.-pod-prod-02-eu; Tue, 14
 Nov 2023 03:15:29 -0800 (PST)
X-Received: by 2002:aa7:db48:0:b0:544:224b:a4d2 with SMTP id n8-20020aa7db48000000b00544224ba4d2mr7245359edt.0.1699960528779;
        Tue, 14 Nov 2023 03:15:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699960528; cv=none;
        d=google.com; s=arc-20160816;
        b=WKwjoqpgrPI+x7WbrigvAYpw4YoZOgaZ0CT2dM/iXc1P2lFeE1h7zc8nkFROTAMtHW
         afBSSLKUI+G0ivDV59/yqrsierlkmRxjlL29vi3nktRLHVgffUDmyVSgyfUkL8PZPz7o
         6cdF6RDuRNfix4mzB7xFmQeaRcc5GCSOnbwh+4QybyFeTVkbaa8JHOykJ3py8+8qT3kJ
         toZps6kP/5+FvpTWgmQ3N/g8DxB8CRRILQyMtVSlhakQVujaVT2WJdPtbOtN5ZlwzV58
         Rydar+KufVpEAaWCmzB4ieeORxE7iqK/IPixL8ZyLsrGWN1M7nuJ+FSqxTUiUDHBFqzw
         B0Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WjY0lOqg9mh8mWBYE0KXFzU0LNPphr/5FnE4BKt9JW4=;
        fh=nYtaDO5H8e3I+e0Fs1cFZXNS6k7fh10G/jAvTGFgWoA=;
        b=phn4s8GsZhWli/pIfYHxTb+emSIcZ6BBzmt3oNzy7FIPJcHPJ7mkuwOJ2rK4LCI5Ge
         ok4mg4OV1CsICp6qgm4c0tRPqt69zxciJIjVR0UucR0MzleE/6UxIC7iTicB0PyFpj6K
         Bo7kAuJ8uzfj2RsvAAP/B0ZwIkPDaqO0WxwPU/WMrX+2esLeooak+tpVsMuao1Lr+xEB
         XXfziP7PFUSLLvGgzqdhe20duB5sDwddk0zCxK1aquHSZvog4MlusQTbZXVFMPtxw+6N
         3gwkhOW+xBTUhr/L8XoHQC2Wd6MMXnpGeflmFCr/xiBCcelXwgISs9r5TmDA0S/BhPz5
         7ieg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=bKiv6KUs;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id p15-20020a056402500f00b00542da7908e0si342934eda.2.2023.11.14.03.15.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 03:15:28 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 227F92189A;
	Tue, 14 Nov 2023 11:15:28 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0101813460;
	Tue, 14 Nov 2023 11:15:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id baPYOM9WU2VzRQAAMHmgww
	(envelope-from <mhocko@suse.com>); Tue, 14 Nov 2023 11:15:27 +0000
Date: Tue, 14 Nov 2023 12:15:27 +0100
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
Subject: Re: [PATCH 13/20] mm/slab: move memcg related functions from slab.h
 to slub.c
Message-ID: <ZVNWz4lYwnRVhRtl@tiehlicka>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-35-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-35-vbabka@suse.cz>
X-Spam-Level: 
X-Spam-Score: -4.63
X-Spamd-Result: default: False [-4.63 / 50.00];
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
	 BAYES_HAM(-2.53)[97.87%];
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
 header.i=@suse.com header.s=susede1 header.b=bKiv6KUs;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
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

On Mon 13-11-23 20:13:54, Vlastimil Babka wrote:
> We don't share those between SLAB and SLUB anymore, so most memcg
> related functions can be moved to slub.c proper.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Michal Hocko <mhocko@suse.com>
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZVNWz4lYwnRVhRtl%40tiehlicka.
