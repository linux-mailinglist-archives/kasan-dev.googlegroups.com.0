Return-Path: <kasan-dev+bncBCM2HQW3QYHRBJO74D4QKGQEXGGFRMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id EE0F22451BD
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 20:55:33 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id t12sf4804277wrp.0
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 11:55:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597517733; cv=pass;
        d=google.com; s=arc-20160816;
        b=V6gFj9LvO/tqGeS5XFw3ckLU4S4OfPL2muHYWC8O0aNOho8NGmVK2Q4u3wBZZZ8hIY
         ACrED62Ltm5QfVL8oE/jk7ZFlh05RtEWtvv1KuCYbkvfH01K5aNsx6z94nPWyvOEIi6R
         KVLCRdIZ/IKIrqiwf1chRBzNULSf0lG60pc0N3Agk9II0IiBBubOrF4SiEAPPZrODXvT
         SY2yl/7VCihYT1epjXTRPo+96OBvkUv+IUC52XFSi9ZTpdfUZ+oVlv7vsGzcnY+a6iO1
         T03EfBLkwmdNGpkP3sF4X3qifT3TRcdRazX6+hVqpqog9ik/sxaWci8UZvQmRHrFzfoD
         1McQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RYGHobPMtSXLQz9HXsMVu6/S0IBF+DQy91B8i1ibbGE=;
        b=HKY+mAeHjXs3sRmJZmlw4NeL38Tu6j/y2MHmIJpdUhYthCbzkyF59fd/kc//5j0KKz
         RUCJJZ51CFY5W4rRSf0EIXRukrTIYKhIeVI2KXK/uCArQKe+vefGal+OGR2xcOocqKy8
         RMusC1caRB4IDbDITsAXKsldKAgAQeB+n4hFLVqkBPcayUdz+69RUPCdmu8tZsfZ3Xs2
         KvfMYXlHCe+Y/z8y0sunE/ZNAwA66rZ/K8xRkSJ1mDpvqCKmEKF9i6ZgIxtBASE4sWTd
         zNvUa380Ktw85E2Et1lJcqZAS4yhHYkT1joTd55TMjravK99CIwfnCYU0xI9/RpHuVoO
         xq0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GPHj7mF5;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RYGHobPMtSXLQz9HXsMVu6/S0IBF+DQy91B8i1ibbGE=;
        b=jspkTNm9qh6moPuTKwyRq9A3Uf5/bZqufxdFdVic0LD0faw97wcCmB17+boP/ISAT7
         RcTI/eFP6GtNsWqtCYkN6RF8OsX89Jjl8jV5s5yKIbTQVY05o0IgFY6DEcf5wSauyrqx
         hpp3puSBw415GBW9BJhTsgmsr73YNx34Nn97GhYRyblLnDbYZdlLxn90zhw392v1w3t3
         14lvTV2TFfyJs7D8/LOHfTOC1tMCnsPZaGG7G2pMN+nbDeIihvMfq8DYoGSE1gkCanOd
         TNnh/tiAHCHKJyC4DJigRePuZdEpVp/CyEuBsgg811tw7zsGALCOMnavsyoM4hdbhBeR
         bMOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RYGHobPMtSXLQz9HXsMVu6/S0IBF+DQy91B8i1ibbGE=;
        b=AL9aryk2s5cwOIf5iEPLmTzFcyWm2g+dgBTYtktQTDG8JUCcLWcCu1Ev0KEnm/KLic
         5q5PFR1ul9VS+YwfvH+AhsqFxzO5L2yJ15y4UMd3tBj8KKtFYWNR+q4mHtXWi996i7Vm
         SklEL6uucqkGdXjEKtL7FH5Ex3FPn+fr8R/c+/Z1MAaqzkjAORkoVE18PoSFlLuRSdyq
         P018bF9bKLx+U4AWKzDsEMBgXVwwHQHNfrnDSoV18HoTb1LH5g6924+c2V3doksnOJPs
         GX35cdPy9EHvMs4uuSXbpyfLxjZFB8mZkYRIm1rKH8Aoauay9aDfsu7tO0AibnHE1EP+
         RDEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532irYULtHp6scIT5s2AMuX1XCMC4+/8+6Bqw9NXaywZXPJohAp6
	QSYoZh/5OFhJe+sbqRlrL+E=
X-Google-Smtp-Source: ABdhPJz0TULv+E7900HrDCOL4Zo9+y1gUX5F2hb3Oi+FckE2qDkkHwBNJQFRlaSio7/WCd/H0qHnTQ==
X-Received: by 2002:adf:fecc:: with SMTP id q12mr8134731wrs.374.1597517733644;
        Sat, 15 Aug 2020 11:55:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:81f4:: with SMTP id 107ls2138910wra.2.gmail; Sat, 15 Aug
 2020 11:55:33 -0700 (PDT)
X-Received: by 2002:a5d:464e:: with SMTP id j14mr7942826wrs.361.1597517733156;
        Sat, 15 Aug 2020 11:55:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597517733; cv=none;
        d=google.com; s=arc-20160816;
        b=SeS+ZfVsfv6peowLhQ3ec77N/7OkjdeCICh4dGgLC8dwfj6G1ZTZuIpDNm/7HOg3Ad
         LgZa1jLl2ObdKzBcXCBHfQV28pGutUY+C23a8EWc6QUUvO5P732ScPvzwxUrQRLplm7H
         yQ5NZair2K4WUmTw73jd06dioJkrECYItb8UxlZIU5UR+Wi0B/QDLrQaUqTcIoThuKWY
         3M0uk9CWmMsBoGkNvD4Zd8nA6tLxreNudYMqDsA7ybZb5tTffyWCICeHPKy0unmPTO8d
         MpcccT4GZoa3J7aNsPK+XX5k2nXtKPIgzs5AK+PEdTKhzW+Z+PYQ+9s16w3NxPnz0+70
         syDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SYhsdz9Ikw/5Id67XdrFAG6RYY/GnifUtuavkK2F1mo=;
        b=iunazchnYHU8PSKF9RRbWcAiZo9mCRXBgl21O9AUfgqe8Ao7KaYeqX/CxJamXCbtlY
         +HH9VnF/1YEfEAMuNWnAD7/TQzL6SKZ2reaisMp5ZzN36JVXkk6b9WKkLz5PsC+Xmjr1
         /WuodnTASQRZIWqFk0KJceAAOC6seMBsS1cr8f51VNrvaOt/94EhbwUJtdNCa11pvPrv
         xo7Lgr2ut0lifJVnEnfXxYnaHXCaw89AsemaX+rgObbpdgUSILW/bOeq4Cl11NwequEW
         zm1kZmSKW80EsDMSWdRqxOukBLYCdOF2XUxYDEyYwZXfqtHD27LhZ9BIxndhcdzLDOlY
         JX3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GPHj7mF5;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id j16si410320wrs.5.2020.08.15.11.55.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Aug 2020 11:55:33 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k71KR-00061N-Qf; Sat, 15 Aug 2020 18:54:55 +0000
Date: Sat, 15 Aug 2020 19:54:55 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Alexander Popov <alex.popov@linux.com>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com, linux-kernel@vger.kernel.org,
	notify@kernel.org
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
Message-ID: <20200815185455.GB17456@casper.infradead.org>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200813151922.1093791-2-alex.popov@linux.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=GPHj7mF5;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
> +config SLAB_QUARANTINE
> +	bool "Enable slab freelist quarantine"
> +	depends on !KASAN && (SLAB || SLUB)
> +	help
> +	  Enable slab freelist quarantine to break heap spraying technique
> +	  used for exploiting use-after-free vulnerabilities in the kernel
> +	  code. If this feature is enabled, freed allocations are stored
> +	  in the quarantine and can't be instantly reallocated and
> +	  overwritten by the exploit performing heap spraying.
> +	  This feature is a part of KASAN functionality.

After this patch, it isn't part of KASAN any more ;-)

The way this is written is a bit too low level.  Let's write it in terms
that people who don't know the guts of the slab allocator or security
terminology can understand:

	  Delay reuse of freed slab objects.  This makes some security
	  exploits harder to execute.  It reduces performance slightly
	  as objects will be cache cold by the time they are reallocated,
	  and it costs a small amount of memory.

(feel free to edit this)

> +struct qlist_node {
> +	struct qlist_node *next;
> +};

I appreciate this isn't new, but why do we have a new singly-linked-list
abstraction being defined in this code?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200815185455.GB17456%40casper.infradead.org.
