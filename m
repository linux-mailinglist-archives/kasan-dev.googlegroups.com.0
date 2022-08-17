Return-Path: <kasan-dev+bncBCMIZB7QWENRBNUO6KLQMGQE3RYPE5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AD0259692F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 08:14:16 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id v16-20020a056512049000b0048d0d86c689sf2207521lfq.15
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 23:14:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660716855; cv=pass;
        d=google.com; s=arc-20160816;
        b=g4CsMzWCoEl4amdd3umMp4RzTIYNGViMVYODm4txQbq64+lBHKX99laGGtjvL/AjsG
         HULl3X+xEJbfsZR3d6t9rYx9ecACS72VoIM5IKQIzLi+pYCHFbXPKW7ttCsJCblpKdi9
         NFJZrA/T66YXKdihpPD+IK4pcNz+aj+Y5IoO/MyWau7d+xOX1z7EbmMZUZL9DfQV68pi
         miYRKkzODQGVYKvwZFu8927jUEQDGMi5YamYpQX1Xrg3lwZi3W/NH6jAqOsKvBb5rvzk
         u1DBfwRG0Io7HA6rycz3gQ23Pv9DNSksV5Aeh0n++0H0lj1AkSNnNYtNrxPMqTanDzTr
         tF+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6fTCEUM4m/CaBN8RTIOyWXQbtWugL+NpMefPZly9xDI=;
        b=Nr2AmfY/incT1kfuwcgWZeSwH2uD0DEpU7fKBxe+p9Khn3GI/HgSfSeN42Ln0wpStX
         DUDOMXEW2hSukNWYYxN81nQiQT9pSWFEaksc6IzsflGuYpMNT0jSpVUkae7fkYDWAcod
         SuG1vFoWBg38VZfTFrORgKR8oy5+Di+N3FWhyjjxipSITtw3p3k2ku/7Vt5tn18P7qRB
         vR8VNAf/FkP6XYnF3YlvfiO/euOE9A5fXfm0pYiSWYKMTZrAWppHCp4qDNqS9sYsPMaA
         Jo2G2cv4iUrhKTkFx50uppqtwrjAvIUToXD2dJ7gC1gkUkBCl3TIzXvemXBH2Sio706g
         AFVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="s/1uTUYy";
       spf=pass (google.com: domain of 3nyf8ygckcvqzhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NYf8YgcKCVQzHKG6AH2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc;
        bh=6fTCEUM4m/CaBN8RTIOyWXQbtWugL+NpMefPZly9xDI=;
        b=pQUMQjGHnf18iKK8POEKCTR/9YRidcLV6g1gMSF+AverzHH7SJ886mE41ss/Cj8qsJ
         Nd/HIL5dcisttiK8peUeVAuep93YAK56zBR9qsgHYDKZSjd79WrS2tWVhtn6lSMln+w5
         Qvqa08v1Xb0Gr+P/4I522iJ0BfYX1AGsn3ImjHvieoun2CRhqS1ArWAQAIAHrD9+U1IW
         NSh+DRu6yNcn58eI/IsUI0q39YpLiHgW41LIy1DZtmkvytsvtpZIMJWR4gatuWx8ErzT
         NCcj2vTJIdAkH6XKadjl/DR4js6t8fkGSSMz4yUM0+qQQcPL465npNlTxMtC6g3BHc9S
         Swfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=6fTCEUM4m/CaBN8RTIOyWXQbtWugL+NpMefPZly9xDI=;
        b=5jC34pBBnjZDOJqr6ankHPVYZnmEiYpajFq2E1CQyCZS/n/Odpg63pFM34tBnn1Ols
         FQS9Sfun+AqPYbib/EV7/MVbs9fDfbi0+3FVo8ZdtmMvM+w89kfYCKQdZMjGOnI4cAkW
         lVkZL2Jf3IkUFnQ5ptI86ukWfNqPEfusQdaYmpfrhRJKn7jnVl4JodzAgA4FCpFalggC
         AlKiB1oOcygYP8274fgrDBWw1tvkn8ujhB0dXTrQjA+7WcQ8tVLqDLK+YsfrQvrTSUlL
         EfxrGHK+D3/brPgOAPTPxn5ToTe/4erBE/ik/H5hLYpG6HV3XkBogmabJjjQb0T7ahch
         7GnA==
X-Gm-Message-State: ACgBeo3BtZQXEYtNXvkX6NrAUR0Ffv/zv6MezoxQjYg4oSSDhb6Beqmc
	E8kgxdUkjIpZ8bolhvnWgY4=
X-Google-Smtp-Source: AA6agR7VDbJb/33VYcQjlKVn6JJgozknIk+4GIPOWcysleGeKzIkw9TgRqpOwrqTlPA/+xSlfQ5jeA==
X-Received: by 2002:a05:651c:516:b0:25f:f52b:3c86 with SMTP id o22-20020a05651c051600b0025ff52b3c86mr7334041ljp.523.1660716855163;
        Tue, 16 Aug 2022 23:14:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3148:b0:48b:2227:7787 with SMTP id
 s8-20020a056512314800b0048b22277787ls4849919lfi.3.-pod-prod-gmail; Tue, 16
 Aug 2022 23:14:14 -0700 (PDT)
X-Received: by 2002:ac2:5324:0:b0:48b:9643:3838 with SMTP id f4-20020ac25324000000b0048b96433838mr8666193lfh.373.1660716853967;
        Tue, 16 Aug 2022 23:14:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660716853; cv=none;
        d=google.com; s=arc-20160816;
        b=m7wkwaPRq08jbWFNq8kVwYQw0wQfY9H61BK65u40FOlSaA10EFIUHZTFt4UMPs+hly
         Vv4Zoijq/M4mS7H76OQT38SzUDk7qgUGlrXPMJpIahdjhUS5QOgWHoPt63Uzx4SZF3Jj
         H9pY6JPcoVbcH3N6EBAWWD2n6Rgc4RzL4x46L/DdgeJtRhJbJZIVbcdnKBVhAG5Owvpf
         rpUceiheiPDUhiW7+eWJie0Led+89+txtHY1cfBNpL1SNJlEFA7KynVU44bpZLmfqwoM
         4f/TT3F46P2rEdaBpK9+4CtTlUeXVQXVGmT/eu7+u0SxbEw6MKmsBLhNryfF25UXHy8W
         3TCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Xa1Am8o4teQaaL9RutMPnLbxqHkDGkecVOS2SmaoyIs=;
        b=cReDRVc9T2cmdo12nyJ1UdEUEKFpaASV44VpYch7buTAJA0u4CN161Ez+LN7E2imXo
         67DvpqjmzMGW5ApZZBD+N9jyS+n86e0LKr2IUOPUclQO949yL+qmQOi8DmH5OmKey7aA
         Gh3yjqijj2kCEdyKb338Qv66DgYFKM1mexLuLd+zQefk5TooelV5TUHcaGaPWpFkjopV
         lW/l3PusJ6ke0Fv9cB8vi+dTwXJB0NM7aKb6mZZ0z0H6+HAaBzcwwoCSJoYrDK1yfoNq
         Q9Zgh14PMSzWl2bHZ1U014EEnPZmOwcmAeZ2rPLQgnDLqpT5uKx4E62+ZCKhTkSfe5j+
         AEWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="s/1uTUYy";
       spf=pass (google.com: domain of 3nyf8ygckcvqzhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NYf8YgcKCVQzHKG6AH2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id u12-20020a05651220cc00b0048b1f7cab12si837294lfr.2.2022.08.16.23.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 23:14:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nyf8ygckcvqzhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id m18-20020a056402511200b0043d601a8035so8277635edd.20
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 23:14:13 -0700 (PDT)
X-Received: from dvyukov-desk.muc.corp.google.com ([2a00:79e0:9c:201:6b03:2ace:af3d:2660])
 (user=dvyukov job=sendgmr) by 2002:a17:907:608f:b0:734:b422:42f4 with SMTP id
 ht15-20020a170907608f00b00734b42242f4mr14937896ejc.491.1660716853316; Tue, 16
 Aug 2022 23:14:13 -0700 (PDT)
Date: Wed, 17 Aug 2022 08:13:59 +0200
In-Reply-To: <20220815170444-mutt-send-email-mst@kernel.org>
Message-Id: <20220817061359.200970-1-dvyukov@google.com>
Mime-Version: 1.0
References: <20220815170444-mutt-send-email-mst@kernel.org>
X-Mailer: git-send-email 2.37.1.595.g718a3a8f04-goog
Subject: Re: upstream kernel crashes
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
To: mst@redhat.com
Cc: James.Bottomley@hansenpartnership.com, andres@anarazel.de, axboe@kernel.dk, 
	c@redhat.com, davem@davemloft.net, edumazet@google.com, 
	gregkh@linuxfoundation.org, jasowang@redhat.com, kuba@kernel.org, 
	linux-kernel@vger.kernel.org, linux@roeck-us.net, martin.petersen@oracle.com, 
	netdev@vger.kernel.org, pabeni@redhat.com, torvalds@linux-foundation.org, 
	virtualization@lists.linux-foundation.org, xuanzhuo@linux.alibaba.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="s/1uTUYy";       spf=pass
 (google.com: domain of 3nyf8ygckcvqzhkg6ah2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--dvyukov.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NYf8YgcKCVQzHKG6AH2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 15 Aug 2022 17:32:06 -0400, Michael wrote:
> So if you pass the size parameter for a legacy device it will
> try to make the ring smaller and that is not legal with
> legacy at all. But the driver treats legacy and modern
> the same, it allocates a smaller queue anyway.
>
> Lo and behold, I pass disable-modern=on to qemu and it happily
> corrupts memory exactly the same as GCP does.

Ouch!

I understand that the host does the actual corruption,
but could you think of any additional debug checking in the guest
that would caught this in future? Potentially only when KASAN
is enabled which can verify validity of memory ranges.
Some kind of additional layer of sanity checking.

This caused a bit of a havoc for syzbot with almost 100 unique
crash signatures, so would be useful to catch such issues more
reliably in future.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220817061359.200970-1-dvyukov%40google.com.
