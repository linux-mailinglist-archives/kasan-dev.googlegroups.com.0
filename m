Return-Path: <kasan-dev+bncBDKPDS4R5ECRBAWXTSKQMGQEXISEGTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id E61CE548519
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 14:20:19 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-30cb80ee75csf51390217b3.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 05:20:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655122818; cv=pass;
        d=google.com; s=arc-20160816;
        b=G7jn35dlxgkYftQGU4Eoe4M5BZEHHm0Cu6OwO3/pJxOHcKHtSeuOXG1hF5aAtygXCC
         0qdHi4V2dmL5lO6/fbNO8BWKSnb7Oqo5agYCQI4x5QEyt/7r4bxAXTbTMxRg9EUPtOOw
         5f1aRrzqnUJjrLPQ70gK/m23gThVo0AXIvQN8YFRaQNAAe8bQlh+Lve161QqXmYqAjrw
         CXP93TmIhPOrjZLb2oUBACf6bC0raD+GANHccvAgKneRSEa6jcrkPwwFsLEQQJQpg0aV
         CaRlbCF16Ivppz5O7YIaMDZF9OdzcQcpDEQv8LHyVDjA3lm+oyT9coHIpEugQ9XVZCQb
         MasQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=o8YLThaY99Fv38QzgKOn42svHFItXXNbVAHrUfNPFvA=;
        b=iU3CQ0fgSTiPGknzHcZYxE7EQGIp5Aj9QueTxxu8I7MvcbkjSLrI3ufqkWBYjjmM/f
         L1GV2nAlygPAMTi4aiAUmTHYI8eZAsnvki+LZa+ne0K913pHOyPshPnvTo80ecdwiyzS
         1WW2k5dR74cHkUrsGZHcW9nDZoOUHPcVFUMoh0MhWttsjeQtOUPvHRzrxjUMByCUpUAP
         hZq4CRsNn+I243PRZoXxqL3CSGGJtA9h3vN+l5Q43lUzHDzyfLK3F3IB3tB9blQn8JSS
         jfnHeklzgIwOK85v4+vjdsO+kDiIl8rvp5rrrIRlaMzfAfUphxeUN+flfmULiNrxhpnT
         X35A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=HvvYkH2n;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o8YLThaY99Fv38QzgKOn42svHFItXXNbVAHrUfNPFvA=;
        b=frbu99uFcrgqwoKNjc4KXPSneTAauk7pSop/qPWCuIcQczYAXNZwZegUGWMj9+96AN
         Vaok05GDSjff4Qb3fP7ekvOrsFhkfFfHp6cH3t48wDfGde1FyeL2fZ7aGO/gsyCDArOA
         KnxOZyM59XfhcLn2V0WGO7j2W/sO9a7jMVgkLTyYo+knQnVj99q+xupHWzx2TozyxlGm
         en5uX91ifhGpClDESiq+j7AL8zjnwMJcWoBOjttnQLj55fwIcp7cL7oQgK9ElawuUC9t
         doSaQw3gkJrpG2vFY/vCkiaNzFkSVm8MooZBoGNJxQBRi9pO9kwPyYGpbxDQXHPCbL47
         zGgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o8YLThaY99Fv38QzgKOn42svHFItXXNbVAHrUfNPFvA=;
        b=f2m/JPhQpbZIGlBmhaAitfq8nHJ888brGdxjgxf0nuzV5hmFlQSPCE5iV1CRcRV3Vd
         Vj7Jb79/WsaQQG2xHykeTAn3XKqZcYJmICGjdmLnjWuJZdsN9nH7q4oD7xPaTcE9UakO
         WR+y3nJEhRmkO78Bl3+O/hV0M0GB1Up6tV/Vrm+xpGr40vCrTBARQLck6kKzCXr+KZ0t
         rv+2I4+UJ4TliFUJDtk0ZlDMOSJzS7svE7h/mnzkdODsjnR7Rsm7SZ3pSI9i5YEmE2vw
         4avb/XqSALkKRV7ZEwKvNc5WPhyi71jk6Q/GSQon5z196Ce5LNCSLr2kB4+jLRXn9B5e
         oJdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+4AKTT8ExJ5CVWiNyBF2tzK6f7mqN9Bbn4Jbt7cSBCrAXwhEC
	gTRy83tCaDDRGwpvOnkuPL8=
X-Google-Smtp-Source: ABdhPJxBT4frXiEru8ZcIljkg/GVm5fpIlyWfJygDBl3sB3dD+5P1jje6SVgcypo73k/yTmrHMtS2g==
X-Received: by 2002:a81:a143:0:b0:30c:28b5:1d09 with SMTP id y64-20020a81a143000000b0030c28b51d09mr67100417ywg.404.1655122818719;
        Mon, 13 Jun 2022 05:20:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:73d6:0:b0:65d:5fb3:5381 with SMTP id o205-20020a2573d6000000b0065d5fb35381ls3705528ybc.7.gmail;
 Mon, 13 Jun 2022 05:20:18 -0700 (PDT)
X-Received: by 2002:a25:6b12:0:b0:65c:d2b1:edb3 with SMTP id g18-20020a256b12000000b0065cd2b1edb3mr56283920ybc.97.1655122818256;
        Mon, 13 Jun 2022 05:20:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655122818; cv=none;
        d=google.com; s=arc-20160816;
        b=NReTwAkjOiL43JhdRuVJPSETwuPwsni5C1YGsK8vUXETpcN89c20/PjZvweZRntaW0
         m16IbT3nK/nsChN3nYKsU0f75NeGSZvxtLhSOQzDmntBxT6lAN/HbxSLC178ydbV7v6T
         Dg2ZwWmqjnK2HpWp6wl58t1HuBR20Ev5XuqRk0ojoF2JKrlTAmZw8jswcOb6ItwmE5rx
         NtPhPMdYec0n0iUau1StXlHoUKY4HI2ifM9LRGm/nBPEaKxZqONB5dnzh83dhXKJg24X
         ewfmkb4dwyi/KwLSQqHIV2iW9lEeeYEzVAoXe766EwPtnAsdUvveP30CZnBN5Irgfzud
         paQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Z0oEkfDVJe+HvF3K4yQj+I/I4I4F1ajdtFNjkCqfrE4=;
        b=HT7nHIWCO7MWpNI2WCaBRsUl1s3WgKEjnvDZO8SE1NRqIEdaWRwRE+Aw917XzMdPRM
         qwvEphpP7IeQKXawBC0mGgiJn0RcLX/MZfX/404FxW4eI0stiFeknwiaBIcfSOKqyf/2
         7CMFSXzbvzIVjunQBvp2R0fvNWdPVTBac/IP1UBn4luvlRWSrDmFA3Z6+Vhcf0Cv+v94
         UMoTcgEmVJ7K24/bmcvPt6SS1VOxMq96V6EaY7Gwf5mKy0FaX87lc5NCEt8Ql0W5cp/G
         qHj9ck/EG2c4GKuVNwkwZX6qzUx7/f+SzMBIuDpau+o9MAYGuBMJ6ffv3aNaPp0vU0nj
         JBEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=HvvYkH2n;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id u19-20020a81db13000000b00313fd6c4a73si282334ywm.4.2022.06.13.05.20.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Jun 2022 05:20:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id 187so5584663pfu.9
        for <kasan-dev@googlegroups.com>; Mon, 13 Jun 2022 05:20:18 -0700 (PDT)
X-Received: by 2002:a63:9c4:0:b0:401:a7b6:ad18 with SMTP id 187-20020a6309c4000000b00401a7b6ad18mr18250278pgj.523.1655122817456;
        Mon, 13 Jun 2022 05:20:17 -0700 (PDT)
Received: from localhost ([139.177.225.255])
        by smtp.gmail.com with ESMTPSA id x4-20020a170902820400b00163fbb1eec5sm4944428pln.229.2022.06.13.05.20.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Jun 2022 05:20:16 -0700 (PDT)
Date: Mon, 13 Jun 2022 20:20:13 +0800
From: Muchun Song <songmuchun@bytedance.com>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 1/3] mm: rename kernel_init_free_pages to
 kernel_init_pages
Message-ID: <YqcrfaaImHWEYuRK@FVFYT0MHHV2J.usts.net>
References: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=HvvYkH2n;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Thu, Jun 09, 2022 at 08:18:45PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Rename kernel_init_free_pages() to kernel_init_pages(). This function is
> not only used for free pages but also for pages that were just allocated.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

LGTM.

Reviewed-by: Muchun Song <songmuchun@bytedance.com>

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqcrfaaImHWEYuRK%40FVFYT0MHHV2J.usts.net.
