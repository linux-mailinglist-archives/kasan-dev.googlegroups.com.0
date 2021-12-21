Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMUKQ6HAMGQELVMG5ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BD7CB47BF76
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 13:14:42 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id g2-20020a19e042000000b00425cfac0e67sf2955662lfj.10
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 04:14:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640088882; cv=pass;
        d=google.com; s=arc-20160816;
        b=nMUqUtoHh1/kKMp05F8KwbaNfFilrIz9LiJZ2+TIFPeJ55Llf+Q9kttVziAkwSowP3
         7QPRA2gESDMzGf+wNNyTKCdxISLrcQcB+MjwQN5gfFqYMGAP7BpkRELSKgebPqiDmusb
         5CRm5QhwCO7QT96ewhPzPBAQBn2qi1bqIqaVu0IWcwLrr+vDwTHjIVMwIUmgydTckNgJ
         AEb+KotO2P8QK8zEz49+kNpWSXsYEo/SBksW0FMGvpQxhyjEeg5xMB+8QvpsI0rOOghh
         K4i8T+RJKxaG4KJjRxMy3fG9XaBiLJ9BMYHHYLQYPVS0X4Hw1gnRM5UE8kaBtat2yNw0
         THqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CeGCb0+HPXJwSnwJK/o0jG0F9a4IE635eQ5hcQM1sEA=;
        b=qPLVidn9d3xO7ib5yjggRzZJpZRhTLQvtQ3SBDD0Sq0ZHuIMVmyUIM5mexWAzkZABk
         Dl75Oi0oJ5ywT96jNHNs0PGIcevSXffPU8ThsUpetCUeIS75aS6LnENxpDbHTjrP9Dw9
         tXPQVvW2N+6pPbSlE9YWKQfsGkQF1dUOqqaKVKQAZbt7Bsi64wpg0GUiYQFecoS3GS2L
         IP/or1XQ80PBusH5XsYwZ1/Xfqak1JJHzj/rSoJ94bA6/FZEqjXq7Z2fdk1KWXHN1ECx
         rj8jdzhqaOzoHGfD3tyYTxI2UbSYf8uip34esBW0P7z0NyQb6YhUnO8LpBbGIzL5opAk
         5F2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kf5FSZi9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CeGCb0+HPXJwSnwJK/o0jG0F9a4IE635eQ5hcQM1sEA=;
        b=YZBjq0FDvFujVfpFPFniAuP0xAqbz5j8/Sd2yKMYINIqKBTe8LiCWjTMr3QEroqfcW
         P0yiHDybkmC1wtiXtdJyL7PLMsNDMHiIuaYqdTSMjBapiISz121XCVciyMSexbEpMVMy
         BeKTdBzDw2/aWfGgqo2zHNSO/uUrSW7/dO3pwI7zBnAuNC8J/yI3xBy6JTussHAZip2K
         nE3GuoDPuqaQjnLs8kGzVRMNiEchYIrwLzRczM1DJKxNCY5526MwrbOM7NPxm4rQ3HgN
         tnrf6NMQd6SbR0BlpEqGDxs4C1yWFGJlAEkBudM9EsAZq70Zn3M6v/hmyPCP9SObDnr9
         j6uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CeGCb0+HPXJwSnwJK/o0jG0F9a4IE635eQ5hcQM1sEA=;
        b=M/Uk8vj9UY6stR51Vfy5Hi22MeT8WkuQXtAmvNFo2r+v7kEECKAjw/Sgdeszy2eJOC
         3Gfy4c1/b+iBMu4ABXH3GXgRjLi8KzwfL+pHL1aaK/C9TCm15gKCegi6llG1ESkJRJI0
         ehKfVoutMQHdeUZDo7pIdllo+PHRxXFXibSrH7rWf0IOv0Psk9xP1WvJfgoXUnrXl84G
         Ctsw7OuoWsdb4IOwc62WkQ+tbU5KMafMEdUzdM4kJsdXGfm0s5quRJ3gB02Juuh+9GRU
         8JBi5yejAVTpCTqK6vdREfCeg9TFjBgHOmSA2bS+8wwEo1hxkCRxboGl4AEAIs6z4HF5
         CG/Q==
X-Gm-Message-State: AOAM530n/VgJ/NPKCvh3yWcHo0LAFgLotp2NHZBx7w6KT0D1bjLw80Bi
	Utg0sii6d+Dp+tUbGgwtGD0=
X-Google-Smtp-Source: ABdhPJyeSWuRmBSQxX/hI7rZ6gdzqMFN+YaCIAPprnhUj+A7GDculWu/1DHS3Jbl2Zvju9bSshATWA==
X-Received: by 2002:a19:7512:: with SMTP id y18mr2877416lfe.380.1640088882195;
        Tue, 21 Dec 2021 04:14:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3389:: with SMTP id h9ls78412lfg.2.gmail; Tue, 21
 Dec 2021 04:14:41 -0800 (PST)
X-Received: by 2002:a05:6512:210f:: with SMTP id q15mr3042352lfr.112.1640088881085;
        Tue, 21 Dec 2021 04:14:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640088881; cv=none;
        d=google.com; s=arc-20160816;
        b=ChzgsRKxuIYhr99RFa2lDw+4z72yWrT+Rr/5kbrav2FDaQhBqPfeD8GbDfilzhatwv
         Hgj3Oz3h6xK+yNaKcgzGtl0SjtgwwNfqtM8zVzjEWhRhTDISJ99BeZDvKsRs2lIvX+0s
         Q/AFyLgfi1kBtz0P7cSSZoeKfu0hU3Jz/4V3vV/5uXahe4zH/n7lPwG78YXZhcQU+8O4
         +QDAWTFbyNuh6lELa9K7TzL7wRiFIruyWUe1nt8RuLUHJLWovYUhSpk4KzlH6+lOIW9F
         QIaifgUUGPQsY2TuuNxDd3f1MI+07NirtsdkYQdRr+HxM4txNLAXLHI0Yok+O8nhTSQl
         lYSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NYtFuw8skf4IqEe2E5F4oiyYNk3w/W3sUef4AJQUX7E=;
        b=g9ZE8Wudp+9lUptiX4eySqJwXLuiF+Igg3ED+C7qvinm6mPhGHWJoe2Dqp4i1TdHX2
         Luh8mi4rrg+sy3xnTsqYsrw/92n8LJZ6WFCcOIqXh3PM00sU2J/1CziS9IIT2nf3CX8r
         oZwBkrH7yNDEa6DJcyR+bsJ4rSjYWAWIorueqo54QgozUVj/XNNSxP/ITnSKPHgPw8cI
         iZkI611Lt/Qqo8H59i9QJDUC+BbYy+/mnrXI9sxY1NjqntDY5x5tRtk/zbP/VeB/Qhts
         U3vCH/Vvh8DUR0mt20AFpqy5TPS9JoiFPo2b7H2wlHcbrDRkiaA7jiCIe2aZfS4Jm6VC
         xAWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kf5FSZi9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id c12si970535ljf.4.2021.12.21.04.14.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 04:14:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id i12so8911150wmq.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 04:14:41 -0800 (PST)
X-Received: by 2002:a05:600c:2150:: with SMTP id v16mr174804wml.10.1640088880731;
        Tue, 21 Dec 2021 04:14:40 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:87ff:799:2072:8808])
        by smtp.gmail.com with ESMTPSA id p18sm4326864wmq.0.2021.12.21.04.14.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Dec 2021 04:14:40 -0800 (PST)
Date: Tue, 21 Dec 2021 13:14:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v4 28/39] kasan, page_alloc: allow skipping
 unpoisoning for HW_TAGS
Message-ID: <YcHFKSNDI8KJKR7y@elver.google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
 <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kf5FSZi9;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
[...]
> +static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
> +{
> +	/* Don't skip if a software KASAN mode is enabled. */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> +	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +		return false;
> +
> +	/* Skip, if hardware tag-based KASAN is not enabled. */
> +	if (!kasan_hw_tags_enabled())
> +		return true;

Same question here: why is IS_ENABLED(CONFIG_KASAN_{GENERIC,SW_TAGS})
check required if kasan_hw_tags_enabled() is always false if one of
those is configured?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcHFKSNDI8KJKR7y%40elver.google.com.
