Return-Path: <kasan-dev+bncBDDL3KWR4EBRB3GNT2RQMGQEC6QVASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6529F709C9F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 18:42:22 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-75784a27e8fsf439938385a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 09:42:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684514541; cv=pass;
        d=google.com; s=arc-20160816;
        b=yIdNFbDMQzwOaCS2hIaYbwhDSfx/Ln9eNdy7I5T9RZWAK8qxFOAW4fz5zxnvQ8Th5k
         EtY2CRVq1uwknLVrimpeGM3CJ2b9SI8rJZ3UIyPRTzEE8i5avH6pxsTmoO0bXhqRyztA
         BX609R6HiMetuwuHcQMiTzFB+voC99+QYv0KlOnZ3ukG9J3RCWW6D9+7bY1xkihFqqmB
         0pvgtTPlPB1ht5HgEC/s4u24by2zXLhVXtEEINo6ZrXxc5fKZKEC+AU3H34+eacXhAHv
         2DfAernuKbCA4m5TZAM68q9rSsITvWMQU9wWn8tNb1M0h0ymLOcks2ftMZxLvI195+h3
         fusg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vVLSmQn5kCfqu07xDCysZSfnlZBnPHNx6hi/ix/FGVk=;
        b=qEno/Zfvro5DxzjoN8QLktLXvqvPWkxMcCJ8cXRuU9B/2XKUWsoVhry2PoILIx/xOx
         BQoJ0wKVGngKsqv0NcJkZlDJukye9D4SgsenEizsNccdOXG1ZyELTiTA3KkET+qpNuWN
         rSTG9x2YFxoIg8NaqbwbKyrBFVK9yl0wJ9G+WHH9WpkQbdXUhyklhPXojoYSwnh4VQz5
         DQMqc8BaTD3E5PQ4/EH3Bm8NRo8sUebzjpywa6Ztth1LLERZ8sciNYUtqfm7goYw0VOi
         Woy0Tjb4pC/8NQyianf5+6L7mqoL0yLtyEydXswRupjpl7PdLSWpPp4jsMu3aYYSXu0g
         KEPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684514541; x=1687106541;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vVLSmQn5kCfqu07xDCysZSfnlZBnPHNx6hi/ix/FGVk=;
        b=YF3vY11ujuPNQDqzOvPj9NR1OHjZU/cQfOIuww5GVdp9pyVWec7HwZsR/Z4/nhWl0Z
         xJReVRYwhZEuUew4WO3rMkNCatuEByS29IzDB+PlS9B+4EZ29L2OvHTMr4In6970QNI5
         q6Hod1BIYuTK8yRXKc1Uu8HygNQu0RqMz7qAi0m5ijtFyKVL3mhNNgXlvS6iArf/G5zd
         p5RWUy6oj9Na+4wx4/C33MUSbuwhP8WDhIU8XgTO/plL1gkwgla/Jz2VsWFT25kdDcfd
         wGEKpWnGZbj5QFGH4OHIJq9kQDXpUgNv1Meb2fcC8KFn13lzVGv367/O4FrSOrYeJJ9C
         IzlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684514541; x=1687106541;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vVLSmQn5kCfqu07xDCysZSfnlZBnPHNx6hi/ix/FGVk=;
        b=IJ4D0ohHjLBpGDgOtmisGxK6SFTGMt8BB+UnaXgTBA+3dlDkiHdAHrdgt9E1I+mrIX
         9lP3no98WRml9jWrJAKtVrXSkJm0UVtmgVQk1sYwhLizabTxM+2MgvblQ0Dznzuuh0Jt
         LVmfyPupb8kNk82KINQJJrhI2JUM75a6yDgNWlvlLa/Rdv3c+dRWPTi6b6XvOidcOZee
         11B7t6bVF8ZsMTimX6Uiv9K5zHwLAnv01/pTQaMORzOoLv8PPIbC9x5GbxOKsCETuSME
         fzsg0A3EC5LCkcMurDA+FlfSexWoWMk0SYptXGbw8gf7w9F8BO15mxvUsO0ahmyP8mBl
         n80A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzsRwBdLtQIfQgQKYI4ddpP16GyeDSWy3K5fpR13aiiLlG09cnP
	JzXKeG3ERJdpePfplbd36S0=
X-Google-Smtp-Source: ACHHUZ45b9BFvAkbRtDptAUzjm30zg3sG92iW9cd1SmNU/oDUFbTG8ra8j1+ymJ+pWJMUTGIvD4iAg==
X-Received: by 2002:a05:620a:2a0b:b0:759:67d8:6143 with SMTP id o11-20020a05620a2a0b00b0075967d86143mr736769qkp.7.1684514541064;
        Fri, 19 May 2023 09:42:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7201:0:b0:3f5:1b21:6b16 with SMTP id a1-20020ac87201000000b003f51b216b16ls4183136qtp.1.-pod-prod-08-us;
 Fri, 19 May 2023 09:42:20 -0700 (PDT)
X-Received: by 2002:a1f:5284:0:b0:44f:c14b:5610 with SMTP id g126-20020a1f5284000000b0044fc14b5610mr1143116vkb.3.1684514540433;
        Fri, 19 May 2023 09:42:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684514540; cv=none;
        d=google.com; s=arc-20160816;
        b=TdzPOe5BeNIikdljaUMRVAgdu+3DArSyzmLna9HU1vwZzoQTQ26YG5s9phcfBK3yWR
         e/hPOhhn1+tJ8xpCfj7OoVCucqhTZNUdfVaI4jkawTPDcsJPbPTvwTkLCWFAERyaCj00
         Wp12mvvTu6APpV3pPkWv7C3g7iiBrfzfFHjZteI/E2fEeAcbm94f4j8UrPD8tLJ7Nyd2
         78i9ESmwQ8GIn6hLrHM9fy3KD1F0r/PDNSFVnqxlR5sHncMv/W4cVaNll3f4KJR+v85S
         YHC47tkUEoMlvd8A3pM3lLRb4SjT5UyURDiTIUbO4OoXav2fg1y2wTgzmz8BebEsr9BS
         aLtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=tI3pILZ/sb+GuKG+RKppCAv6vko4emUSZ7mWrZSZD4s=;
        b=MF7405bv6A+4rKr4QxqpSab5h1Uf+cnE20uY6DoSQGX4IiIgnkF9WE/uw6P4Jf0XCg
         i2SY2OE2bfXO0+pCC7VULc76VOa6Wrs9BRFkgkg3B0xXRDalKccF+sKz2esi44sdqbrZ
         SRkQsCyBJXbWLHYUExZnDCnEDi0+cya9Q/tHC29mAB94tJrtQUa6vTX5yoaTqXdmhPP1
         j5LM8OephWPH/I5+OJGQnTd9CWOcqciYmzJP7GvIvYLKyOaW9XU1v8gs0w+7WkyE02vI
         ULab6/9IswUOJ2LUnaq0Z9dMt0MslAW8cuSap4o1Xrp4vhEOMdXMs3y5alpfYv1/nM5B
         LH9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l38-20020a056122202600b004401f15502esi271049vkd.1.2023.05.19.09.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 May 2023 09:42:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EC4E16592F;
	Fri, 19 May 2023 16:42:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 921D1C433EF;
	Fri, 19 May 2023 16:42:16 +0000 (UTC)
Date: Fri, 19 May 2023 17:42:13 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>
Subject: Re: [PATCH v3 2/3] mm: Call arch_swap_restore() from unuse_pte()
Message-ID: <ZGem5R4gw/w0K4iw@arm.com>
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-3-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230517022115.3033604-3-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, May 16, 2023 at 07:21:12PM -0700, Peter Collingbourne wrote:
> We would like to move away from requiring architectures to restore
> metadata from swap in the set_pte_at() implementation, as this is not only
> error-prone but adds complexity to the arch-specific code. This requires
> us to call arch_swap_restore() before calling swap_free() whenever pages
> are restored from swap. We are currently doing so everywhere except in
> unuse_pte(); do so there as well.
> 
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a99ae05d6bbc4f

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGem5R4gw/w0K4iw%40arm.com.
