Return-Path: <kasan-dev+bncBCT4XGV33UIBBJEJ42PAMGQEQ5FH5MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C5940683873
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 22:14:13 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id y7-20020a05651c154700b002907d8e46e4sf612976ljp.6
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 13:14:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675199653; cv=pass;
        d=google.com; s=arc-20160816;
        b=AEgq0EzuvOdUXl/4biimKKSIJ1Z/sUtwPdZRITYoohz77HA3DZERJd3OAw5WDVCmug
         bqVhR5IzNhRDj69zj8M4kBVBFMbQfny2HFoLi+hd041jmv7cw9YhDX+iSExYmVRy4d+5
         lsdTlSiWhBVNSrM16FijQ6fW5JCPX/XjcHC9YGUYs2yosiK+ICG6OIltNWGZqgHM5dMQ
         xUNmozvvK6Mfcw+UYOTtotJNajyWZi0Nsu0TRs5vPsSqX5UWo8lZCr/wIt/Tejl3P5Cz
         ZKXGTXbLjFxRMnbVWR0WW3OR6dsVrV8TQ2V8idGRV3tKTM+QwmGrPgGvOe5fHiQpSHJb
         0/Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hTvw7MkMOZ208IzFuACl58zPMTVcp0RSEqv277VqO9I=;
        b=GQdmRLrVJHz2rc4ds4qL/Ni7ihXo3aJEZkl18adYFZGc7awZJmcM/hV78FyfEeG+K0
         D/Ov5xf84KhkJdHDGPvfOC4wOUswhMh0+k4LctYKDwK6nxJm/ncMtDUeSPkGB5ZbaVTd
         pZMGTVvR/DYgEQRAYxpaNPB0T7eWR9KDTZFnRbeNoHwRl4G8Pw04yoljglg1wlHCeVrs
         7ht/buASPMFLuetlrap0flMu+Fx1eo6v97OAxien/vko2aDXrvjN8m2ctO/8dsAjLqR/
         tFXQzlEBB42cjgVlnRMoIq/OFt5zOXyF9xB8wTF4Bi6I2Nt+jIE4cR9hlx1AW1lWlEj8
         kQXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i+eNCGEG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hTvw7MkMOZ208IzFuACl58zPMTVcp0RSEqv277VqO9I=;
        b=FPtfP4rKyim3bsUQGVV2vs1IbgFGeMwdfgdNvKqj5g1MYzxreSMkKiX9cmX9COlZXX
         0QevIj2py+4r/76CEtWR6Ts+lDeu/bDzFIUKXxMINcCGpGoL168eR+sgFJUR995O7+Jp
         xIbxxyF0TTih2GGLDXevWGsSQvSoBf0SXZcpKkI3S4RuVWX28PJeF5h9HdG+qo3sEQS2
         l0d3s7gUhECLyYcSS12bVLWm4UyRwroU6MqAesXcRn+pwsEzPIJx7z1OG0sWe9WzTqMP
         Uqfrz92IY57Oy58HIWxBnCXSTzPttF5GXcKCDl5sVsEBOe9mbKplK64wyemsQrPu+qL6
         1ycw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hTvw7MkMOZ208IzFuACl58zPMTVcp0RSEqv277VqO9I=;
        b=pgBC2jKUDiuNJ5njMFCrWMDxVwZSVAN8A1TsS42tYK9sQye34TH2w5obYsdafij26L
         p+SLU9Et/CEhlcusfxKbNA5B2eQkYhmktVztK1g1YIDJukdTErapOg3fOL5TzygSC0f+
         50RJxEggLIrzcm4pDDaUVO7gQLL7BFjEkEaLfxHgxKt8cFSpT1fRUbPj1FsoO962miwq
         R+fuHDh2q6e0Cx/q8D2RVNXVKrEnfKpSA9qgPDpeMyps5zMtI4nC7Z6R7YLpNM/lxLRQ
         zBEJtoyihkdZGknlzyNhqZjBXjdpm/dMxy/HN3xy5DsjzOSJOTZO41GkxLhtBK5o2EEI
         i7sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU4fEj80KrnsbA7FFnTO9Eu2vqhj/ZOcbJiU4jUq+bqVp+PhUUZ
	Dk6Ppaw7UVO1MgxriXNJ3G0=
X-Google-Smtp-Source: AK7set9ASRlCXS9NVGmXe5N19XCbwT815KgFzySaREJNuWA6pvwFbjgs/9jus8X4aaZ2vdds8g/obw==
X-Received: by 2002:a05:6512:308b:b0:4cc:8589:595b with SMTP id z11-20020a056512308b00b004cc8589595bmr130263lfd.0.1675199652965;
        Tue, 31 Jan 2023 13:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls1329626lfc.0.-pod-prod-gmail;
 Tue, 31 Jan 2023 13:14:11 -0800 (PST)
X-Received: by 2002:a05:6512:39c9:b0:4d8:68f5:747b with SMTP id k9-20020a05651239c900b004d868f5747bmr3126815lfu.37.1675199651065;
        Tue, 31 Jan 2023 13:14:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675199651; cv=none;
        d=google.com; s=arc-20160816;
        b=VRvt35MWtUpV6b8JsdzmhiWy1nYq35zWUW+tEmReyT8An39jBiQFYfG28K42Y1cWQw
         L3nxDtGzYMe6Zo+R4BU4Gq7r9mh2UIMEJYlM3/Dkz0rd/VLOKtAouYub2ivUeDtUOcwh
         OGZM8A9MIFmMhbqqnEHlWDSzngILlLdgKI/s5I1Aylw1/a3XK/9zMc7FoHMDlxZqvCgx
         OoTFcqoNSaCrj6FDAITUMF4xvh7rbSGQeZlcb+bgVgJalNngmZjxkiH1rMxtVHaksZ7k
         8CwbIgTe86UYGMvvK1GMhkA3eyrcufyMVhCJMILx8rRNQxuiLTFEW5wyE8j1RCezBGsG
         yDJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WoAyIb2wqJPoULrOHXdzqBUyUUSgJtNqiWx7gfoyZ7Y=;
        b=eOJn2/qmyBw5NXDDpcqS6WkzF+6o/0hBv46t3ABOhTuPR63hRpSBUhdFARtHjHCSUW
         528hOrZfSKIxj15TeZDiCpfUwZ5/svatRca6vbYJDJWgMo9rAOb2Df3LvotzNyN3YMaj
         09cGEL3GlkeTvS/YUjySflaJrzpddjTiu70vqHdjXsDbP7+4PyM8elf3DSfD5nwA27G1
         D/HHEAO59ttMy11VgXR3d/aa8bu2ZezkK6J1qYnHYPv0mazHNArWZ8s1aGXbgYSWhpIH
         AP1zQETnJmtQw+UczS3PWt5JIDdbPkMSS+s/0vEXU2dvxZQhTSlrmnAWknROKFz42RMh
         EyQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i+eNCGEG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id y5-20020a056512044500b004d579451cc2si958867lfk.12.2023.01.31.13.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Jan 2023 13:14:10 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 7C234B81E6C;
	Tue, 31 Jan 2023 21:14:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EA18FC433EF;
	Tue, 31 Jan 2023 21:14:08 +0000 (UTC)
Date: Tue, 31 Jan 2023 13:14:08 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, Alexander
 Potapenko <glider@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Konovalov
 <andreyknvl@google.com>
Subject: Re: [PATCH 16/18] lib/stackdepot: annotate racy slab_index accesses
Message-Id: <20230131131408.ceea0a762d45bf94c1387367@linux-foundation.org>
In-Reply-To: <CA+fCnZdwuAm-fD-o2Yq86=NgU=YympuwAmERN9KwjpYfkPeYLg@mail.gmail.com>
References: <cover.1675111415.git.andreyknvl@google.com>
	<19512bb03eed27ced5abeb5bd03f9a8381742cb1.1675111415.git.andreyknvl@google.com>
	<CANpmjNNzNSDrxfrZUcRtt7=hV=Mz8_kyCpqVnyAqzhaiyipXCg@mail.gmail.com>
	<CA+fCnZdwuAm-fD-o2Yq86=NgU=YympuwAmERN9KwjpYfkPeYLg@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=i+eNCGEG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 31 Jan 2023 19:57:58 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:

> On Tue, Jan 31, 2023 at 9:41 AM Marco Elver <elver@google.com> wrote:
> >
> > > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > > index f291ad6a4e72..cc2fe8563af4 100644
> > > --- a/lib/stackdepot.c
> > > +++ b/lib/stackdepot.c
> > > @@ -269,8 +269,11 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
> > >                         return NULL;
> > >                 }
> > >
> > > -               /* Move on to the next slab. */
> > > -               slab_index++;
> > > +               /*
> > > +                * Move on to the next slab.
> > > +                * WRITE_ONCE annotates a race with stack_depot_fetch.
> >
> > "Pairs with potential concurrent read in stack_depot_fetch()." would be clearer.
> >
> > I wouldn't say WRITE_ONCE annotates a race (race = involves 2+
> > accesses, but here's just 1), it just marks this access here which
> > itself is paired with the potential racing read in the other function.
> 
> Will do in v2. Thanks!

Please let's not redo an 18-patch series for a single line comment
change.  If there are more substantial changes then OK.

I queued this as a to-be-squashed fixup against "/stackdepot: annotate
racy slab_index accesses":


From: Andrew Morton <akpm@linux-foundation.org>
Subject: lib-stackdepot-annotate-racy-slab_index-accesses-fix
Date: Tue Jan 31 01:10:50 PM PST 2023

enhance comment, per Marco

Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 lib/stackdepot.c |    3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

--- a/lib/stackdepot.c~lib-stackdepot-annotate-racy-slab_index-accesses-fix
+++ a/lib/stackdepot.c
@@ -271,7 +271,8 @@ depot_alloc_stack(unsigned long *entries
 
 		/*
 		 * Move on to the next slab.
-		 * WRITE_ONCE annotates a race with stack_depot_fetch.
+		 * WRITE_ONCE pairs with potential concurrent read in
+		 * stack_depot_fetch().
 		 */
 		WRITE_ONCE(slab_index, slab_index + 1);
 		slab_offset = 0;
_


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230131131408.ceea0a762d45bf94c1387367%40linux-foundation.org.
