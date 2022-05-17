Return-Path: <kasan-dev+bncBDQ27FVWWUFRBINWR2KAMGQEEQBY23Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F46B52A21F
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 14:54:59 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id me18-20020a17090b17d200b001dfa3d25c37sf10565pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 05:54:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652792098; cv=pass;
        d=google.com; s=arc-20160816;
        b=owKPOS4e3gGEsSU7kLNuO3/W82cf2vIySpsmy6G7va2HVGXGrkjw6Ibl3ViDyeeckL
         gRZjOHaOAxG7u3QrFjPgksULSc9l/hDcIc/oLd4hjAMuoNqNm38J4dkYnHudUrWx+sZR
         aHcbZ00+TJCEDiyp3kIxO/5jxUTKlv4CXVmOPyijyGcvui0fPz90pXiffr5SnVQaO5Ud
         7KxM8MsV9RB1U7Y2Rg3QvOXKnO5PbgyhNla4s+Wfke0tpRffhEeUcvwqIv7BLNxCuyt+
         HUovlzU8tBv5XYBCU0BZk//kG5kAhxViW6GOkGtruE0dlDZhZ5p6DGz6pwLUrxOl+MSQ
         MTug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=sSgxNCMD3/84T8ndVUOg/Ou0erG6kD8pG30zolvEXSQ=;
        b=HOjFzl8Q9hCIwlclDEx0Uaktu60sNTBXmYayLsD4OSxz3+o2BWEVasVWbBuj5l2Lqs
         hRpFiI5Iix7AZfoeLelc2NVMZShWYyCFHhZvNrcDSbwL2yq348IBfF+nqoJrZnnOkwRc
         Uevszuks1DBXdZchAdTfE2osMjkVZRZEFQ1tNhsy/Fv1D2UHOAuW0KlxAWVSKslPnDC2
         CsMlbaNArPSnfbrYFqRtP52gwvBGgJtyurxoloMZITu3pc2NyRtPuICgT1BWhcyT7DE7
         nRbHj7BEWLwTU7I0qTf/TZ+aeYGgXJbMMbPGP/MtczrOCsbIY19szxWxvxd9w13zndVn
         mmEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=M5QFBKoi;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sSgxNCMD3/84T8ndVUOg/Ou0erG6kD8pG30zolvEXSQ=;
        b=IbuNPU7jFWejqDDY+hiNdSQ8rSTRoTXudjLw0FuVjarqh016X5yvPjCo3WRdurBXf/
         VgzOusajL7L+YCX77gZ0eNkdxBR7PFruyk2AKARqbQfek8QJOP7c8TsPr3zSXQWGuSOC
         vY+8rj0CzZcmf8rEPhlW/bxiG9SGUGyE/ruKrK/tD+T0e3E/JGCsB4uDoib8wgPBGjKV
         76VkiM9ZYlzGhbIGQ+C34x6s3ZuFcpoNT/5ZVACeKRoPfs4JnJG2RVrSD7tseSk8/Jt2
         8n79/yM8LzqRK1d1KVIpjgv6gLGt8LQDoB4S7LprNG6Kex+IIGPB32hgcH1VsDEJwoez
         Z7Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sSgxNCMD3/84T8ndVUOg/Ou0erG6kD8pG30zolvEXSQ=;
        b=VYENMpXOaZ6bB7mgapuJKzE+xM0Ws6i+qmdfE9W7ZHlRQIXrhP0wOhYmxLcWE/wOW8
         ENiRVg/oc3AegJR0KNxZk7BLtveizCTg4I7WcIDoin2o/woyVXpEBZjWudmrvB1ot5fD
         WXZQhWP7MXusZp/yzQKCfAhOs/IxQVVxV8dFLwA3TbMekmx10HFYS8ng7v/78gMvSNyX
         p9vG+9d8GkpOT05c4Dzka9FFTfMsyS7j6gH6L0DSsq4RFFUckD7P9JTjGGBbV1w3qT/K
         uGqGfVShTJzZ3v2gdBi3aXjvKBfFsGhYPtwZCiAi5xm7UC7+D81RMRGAx2kvijTVw6Ie
         HFhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YfllvxprU7KSczjz0BxIR52nwFs/oVHAZjVfOrZgQux+s9hhO
	O5MpJ8kFum4ac7OgC9gAMjo=
X-Google-Smtp-Source: ABdhPJxjyHqt8wi5H4GdAS1RgdyPIePE2Oj3QxGk446hz927r7O7w6e4hk0RU971wC9a0Zpayurfjg==
X-Received: by 2002:a63:5355:0:b0:3aa:2752:1553 with SMTP id t21-20020a635355000000b003aa27521553mr19788155pgl.254.1652792097853;
        Tue, 17 May 2022 05:54:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2ca:b0:15e:bde6:299d with SMTP id
 n10-20020a170902d2ca00b0015ebde6299dls11818133plc.0.gmail; Tue, 17 May 2022
 05:54:57 -0700 (PDT)
X-Received: by 2002:a17:902:bcc6:b0:15f:4990:baec with SMTP id o6-20020a170902bcc600b0015f4990baecmr21964866pls.102.1652792097154;
        Tue, 17 May 2022 05:54:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652792097; cv=none;
        d=google.com; s=arc-20160816;
        b=Zz32c4cKb6QUWAyd35fVuEGT3H+9Kz7ZxVYNPr48vLJ1TZ6lqFL8bIK4GlvXZ5+jfd
         JFXlCH7RsaTLtnFrxZwd/btSO1JGWyb6jeBap+lIeHFwmAgfYIy6N/9hQqxYjod9nToc
         FgSXfJOP1Dsr3OuZ53g7ffn0UvoeM1346YKKe2fDGFSOTGddNHQ6htdO4jMgdRRukWp1
         qNbXw3qmeWek2hd0+y71DFuAjwptVDUhqLn+JPZzeudQN4CYNhN4LOipceNA70/HbAZh
         1VKkAcOKDtEt9gUfPHE7t5630WVCiHX6Q9L0m9l0WqhDSFE8FC8rgHNI7wAJ81qaHFEa
         BmRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=XExUwsCcYzkutvcAC0xSpFq8c09Som56f645fwHDBgI=;
        b=EkWfEZ0D0ooK/AQs7W+Ubfc7+WEA7qk23wPcuOw7bYLK8O6n4/Se2YrQLDttckCxrH
         PnfJelGmNsUyRhd43d0wjhiKjwB3ORLcUke3kOYQ0Iq/VHnJPSwKtKsyvRK2I+dFJRa8
         +za9jjRUKTwfbbB6M7VKz5MwExOGmgfAc9M0r3MLVXHsfRW32q2fah7AGyXHRtN8CoBZ
         C9QDYJu66dFwUf6J2yORZcwLNU5ckcEMk87Tcn/ETKrHaI4zTZNmtPYijDAZp8eoHvC9
         EH9LOUoj9rUFsJUPnjZtJjk6iaRiT6EXo+enI1HFX2ifNq/fFJ8e/RX1vUyRv2ngDtQG
         bdmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=M5QFBKoi;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id c3-20020a170902aa4300b00156542d2adasi576362plr.12.2022.05.17.05.54.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 May 2022 05:54:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id ds11so5702860pjb.0
        for <kasan-dev@googlegroups.com>; Tue, 17 May 2022 05:54:57 -0700 (PDT)
X-Received: by 2002:a17:902:bf09:b0:153:99a6:55b8 with SMTP id bi9-20020a170902bf0900b0015399a655b8mr21907543plb.142.1652792096853;
        Tue, 17 May 2022 05:54:56 -0700 (PDT)
Received: from localhost ([2001:4479:e300:5b00:70a9:4d53:74b4:654d])
        by smtp.gmail.com with ESMTPSA id j5-20020a17090ac48500b001df40fdf858sm1574723pjt.27.2022.05.17.05.54.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 May 2022 05:54:56 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Konovalov <andreyknvl@gmail.com>, Paul Mackerras <paulus@samba.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Is ARCH_DISABLE_KASAN_INLINE needed?
In-Reply-To: <CA+fCnZcPuVLinRupbjm679b5yPpkqvMrG52jK9rdZY32qJCsvw@mail.gmail.com>
References: <CA+fCnZcPuVLinRupbjm679b5yPpkqvMrG52jK9rdZY32qJCsvw@mail.gmail.com>
Date: Tue, 17 May 2022 22:54:53 +1000
Message-ID: <87ilq48gki.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=M5QFBKoi;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Andrey,

> I noticed that the ARCH_DISABLE_KASAN_INLINE option you've added in
> 158f25522ca8c ("kasan: allow an architecture to disable inline
> instrumentation") is not selected anywhere. Do we need to select it in
> arch/powerpc/ or is this option not actually needed?

My understanding is that it will be required by Power, but I have since
left IBM so I've cced Paul Mackerras who (last I heard) was now looking
at it.

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ilq48gki.fsf%40dja-thinkpad.axtens.net.
