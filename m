Return-Path: <kasan-dev+bncBDDL3KWR4EBRBG4N6OKQMGQEANFH4NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6532B560BE1
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 23:39:41 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-317765eb7ccsf139099477b3.13
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 14:39:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656538780; cv=pass;
        d=google.com; s=arc-20160816;
        b=FglnPphUFTNIXPr9I/0SzfadaRT9SVPpPUhHGlkA/NbES+AyDAFqb3RZSlxpNgL2JB
         JRmrYriu89kZXT4oIIHkvxoNOrNDcyhD6/03pcUBGNcB2xBcInJStlOZytV/NC6mBbbC
         q9RDY7+5h6+rQNiK09LwBSNwfU4URv3tdUQ8DV40ulgs2AiuQPMrbYbuUj4UB2zCgCDB
         +4oLjRITeFTG7Ih65N7ZW+lRQ0+I5oamJWKfHEvQaVt29e2JbalQ92lzbew6uxrb2UVj
         6A6dsZqDs3iTYYMNe3CAizp7JNCGO63QNNNdvzoZS8NsThFA/1jY10zMdUd/3iXPUl97
         hkQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s8yWHK57zjYOT7xXd5K8juC+kYclu36rS2STLUX9FeM=;
        b=NF07v/m8jxuKyBPc2m93AVYGjCYP06UseGZk76gJT/54YH225pWSs0N/OizNU1P0tu
         66bSd5mruPhQAGjhIXqOXQiZd4Eks+p6wz6wPYLoPHnQpm5NR/FBakC2voRssu3sO9ic
         4qA36VBqDJRJH0oWYIaaCv9ih8Nu0/FRtkA2u9B8UjOMcmJ5jvhIpm7fOqNYvn28xiAd
         jNFX1Sg568vWs+QRV55XcXD8yakYQDtuD9xEJPnobTlQ/2y2MANGhgQktt2qJSWmEZxp
         3pBO4weuw2F8a6IGCr61fSOPRhi9ILKVyCTgGEDAQiMF9w0r2LyUF7hk4pRL4t2yVuID
         T0Gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s8yWHK57zjYOT7xXd5K8juC+kYclu36rS2STLUX9FeM=;
        b=lVkPK0SVCeDrgWepxbZgltGa8EfrdzCVeqeKHdVs70rYzRiccXE9cJ4ApytMjjy9YY
         W0yEHv21DQhxPztI6vhxiz0PLBb3RqZfcJZFwjYZrvtN3aVgeCnaU1OXlSoV26o+g6aM
         t5N5438ctEoSnDXNCz1RKxwn7y5FqM44au2EG4waxJ2WyN7AzbPZrLyjdUkgDKJadD+G
         ltp1ATP/jsI0/M4ByWGdRoSetAqDuXbqjQlcuExJTMqwoaQp+bhuHwMKQqIyna8+QKms
         PwcTd4Il/XnUq2esy4Rl1fVU4F9al2L/QMTIIhx0Bs0owslTJpMrp3SjStqKAmLAhb/W
         iqZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s8yWHK57zjYOT7xXd5K8juC+kYclu36rS2STLUX9FeM=;
        b=BbB+ES3pFcZu4nc9Hp8rms6kou8rFWpfq1ASITNxEAipYT/WJqRPZT+9ftGkZ8aj83
         9NQM8ojdpjIuE1LQZjO7hydhyhhIbFdlouD8oA5BTK/OjoqlmhU2Pzq6LLQYJmAbDFMU
         Syx84B9iDMNJJN6tsqW8Da00Wigl9WfYm5YrTPLSdYYjNDLdt069r7oRy8vT/wd87mwH
         rkaGENb/PTGRTD9FCtlQhx8LJhl33gGJnpP7J2XphJIQjtav/rAC68HbnOqWIiIKo2B1
         cfImnPhSWJ+lOtSff7F96mo2pbfvbZggeqOjzHVfBZlgCGLzBN5ivKhJWpZOFSuo3y1L
         POuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9iZvW5vtALxFetT8yiPlQ17kLNI3oehZ4YT2Ze9sp0nwAeVTeV
	cuVQ8UX2jkeg6U3/2T+BDjc=
X-Google-Smtp-Source: AGRyM1t5xPzbVpod8cmSvDALJZD5H20KS2tX/WiPUPa6+17uGlolp9gH189zmDCnEiF4PthkRcFl5w==
X-Received: by 2002:a81:488f:0:b0:317:7514:ecd0 with SMTP id v137-20020a81488f000000b003177514ecd0mr6554857ywa.412.1656538780070;
        Wed, 29 Jun 2022 14:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7dd4:0:b0:318:81e7:91f6 with SMTP id y203-20020a817dd4000000b0031881e791f6ls8758001ywc.5.gmail;
 Wed, 29 Jun 2022 14:39:39 -0700 (PDT)
X-Received: by 2002:a81:844f:0:b0:31c:3c50:d69a with SMTP id u76-20020a81844f000000b0031c3c50d69amr802862ywf.269.1656538779413;
        Wed, 29 Jun 2022 14:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656538779; cv=none;
        d=google.com; s=arc-20160816;
        b=Hie1cNdNL+tsReCGk53FvqRVWNP3T/DThJ8Pb8N3/c/3DkIbRisfYJIhGCWNvI/QKr
         QX8E4IUlyLpaY+/+/311b7O0gT7H4MQRORxIdk7ytZ6qL6SMaNyFhp4oiMEgoUNCUSaI
         LyEVDQJQ45HhloKLFyqdgE2p8bahvRbRyegMA2JqkVJ6qD8k2JomNe/2d8HPpMQqlYOX
         kAXhr15hOcW7mimi2XdZobFlyLGEOVKi4PpQSbtkzOFf96Xeuzs3I6vsd1ibiQZlx991
         AQg2TPqZyl172eBLj49CpjO71tSxjIn0MynYg3PaR9PUkYm/eNreWmAbWMz0fJ+est+v
         aTxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=bslPby+Ydb7eJ2PfH2XQCc1VYqpL9TKCaQhHZ8Wf9gU=;
        b=ZA4VlY8D0vb6nZltNXHwgcEvbD02dxsS9ElkL82bzVqO0m2Z6pfTtrHgaDbZNi/wMg
         Y9KGk9pGKwSyJV4tDPgzjcI8/6HWYSHd1DwTGyaUGfXop3bVluYaQL8uCXUlanCCj81O
         yeUwFFtnu52uuFO9Z5pz2DxqwzLdo4HDG6PR7Dysf55np7h1fFTeEyuoYyjv+qWAdYPM
         UV/176ugu0b6yzD0ocszqnjX6qTPtIZIMkzuEZpJEF/ZjU6W0MPOGbc2k1GvmJmPVdFt
         Rwc8HKoGVIz7KTDX5b7i3DUo24M3Ht3ngqPjXigsZH0hT+SSkyYxXtGTG7EAx/WR/HX6
         P/0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id w67-20020a25df46000000b0066ccd85e4b8si413749ybg.1.2022.06.29.14.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 14:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F2058616B2;
	Wed, 29 Jun 2022 21:39:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 41930C341C8;
	Wed, 29 Jun 2022 21:39:36 +0000 (UTC)
Date: Wed, 29 Jun 2022 22:39:33 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: yee.lee@mediatek.com
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	"open list:KFENCE" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
Message-ID: <YrzGlSUtnXuiuUEK@arm.com>
References: <20220628113714.7792-1-yee.lee@mediatek.com>
 <20220628113714.7792-2-yee.lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220628113714.7792-2-yee.lee@mediatek.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jun 28, 2022 at 07:37:11PM +0800, yee.lee@mediatek.com wrote:
> From: Yee Lee <yee.lee@mediatek.com>
> 
> This patch solves two issues.
> 
> (1) The pool allocated by memblock needs to unregister from
> kmemleak scanning. Apply kmemleak_ignore_phys to replace the
> original kmemleak_free as its address now is stored in the phys tree.
> 
> (2) The pool late allocated by page-alloc doesn't need to unregister.
> Move out the freeing operation from its call path.
> 
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrzGlSUtnXuiuUEK%40arm.com.
