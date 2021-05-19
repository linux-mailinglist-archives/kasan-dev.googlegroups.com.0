Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYEPSOCQMGQEEDYDWFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B18C2388925
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 10:10:14 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id z18-20020a0568301292b02902dc88381e4dsf8437443otp.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 01:10:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621411808; cv=pass;
        d=google.com; s=arc-20160816;
        b=S2f19ShtGFAqKG1cjhRzQh+U9KHEvpynrXZl9gkLDsn1TnxI+a/bBpQb+JOXiVjoZ5
         DeRwmNTrmxSoVEx4LDrwPHmbwmJZxEXfBOeHN7qefMLaBGhrqR4XC+W+BGwNqujpzO7j
         3XG6Umr8ndqzcmnhMw29dlfPNCpGJy9X+0Ne0dsXCiEJMad878bXO03dj0bXPGS9oYPq
         XEOj3WQnj4R8rk21+pIovCJVfYEHKO7DKbK6iQ722JG8qoBoG1QbnfIrQH0x/Vn0mN8T
         LSaY6abhdjOJyBHxqM4hHe0P3BVsrlKO0tm3pSUPKNYnqODdMhuRc23hjq7Rzqrnbee2
         Wgag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FFuQrlNUO0zrRMrrOkaxHYgEtG7IsyS1Vj5L2IL1QEY=;
        b=olTAaSD2D7sZ5dRz9b7yxzqOXfPBv5Lt4+BnECsb3+BO4Haa+9i4oruoAPH4GAmXyr
         YZNorpZHWG0J4jBaXV8f+QmPuppshwqaQGDSA0mtjJ0jPUMj4INim3/7SPsSy6ZIqirz
         GV5ga+EOYRlApHmcPb1UfDSf9FO5TXOzook3w63Fydmd+43FiTOmhrKJ+w3EHv1ZK4P5
         13vFAyqRsaFBrl3KWxRNGXFypPlUvu4ksgXBTTnZQ+71CBq76cYdF039wMee/xg2QUVC
         uD+FtBdyt5id0tnFxe+X49k7q0PDT5dMNZyRMC8TP+6BlKChBSTJaUetfXHMjmvPbpOM
         J7rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hsTBydpA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FFuQrlNUO0zrRMrrOkaxHYgEtG7IsyS1Vj5L2IL1QEY=;
        b=ggijUDS3IxdA4GcYmqZzD/59sqlxplij8dTxPHm3yIUt9T7GUUHBo1KK29Cak0PMSa
         ZvM0Tnm/XBn8un3SH1rCcxXkOnrURTqwWw6ktA37d2k8HEncD1cdEE/0qvkR2WD4BWMZ
         UlOMBzV5OaSrDgLiHbrSPvR1ixPKuMrhYwcwJUseTF3nKZ2r+bPkm7cGk3hpcue2JufG
         HMuNVPVOKRcQAuSzKQTmCbBXyWtbYoAOsoQMUdlZnX2mRCBlPt22fJ3RgxqohzHHGiBH
         lDUm4Nv0mYJTcAcsxAXxlCXmRHMfokzu38BEnmpxgmUWOwQN/xikmTel/3OrOtcuGcux
         X01A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FFuQrlNUO0zrRMrrOkaxHYgEtG7IsyS1Vj5L2IL1QEY=;
        b=CVclZhvc+lWcbvrAuqTi57Zdu9CL6h4iyghN8wLFQKWbDVzTXLXS2hPA/TzFq+SKiq
         l6MApQvtrbpQma5iDDN06mei0sfAkWNAcMvplCSkm6HgBv8FgJM/xa++63RzZ3Wzj9Mw
         4Xp2TiyLfMgtQ0w9n7SpST4lT5cdnxyRZ1aucBPoK2A1eTyXol9F6uWEiFOr8bUA6d52
         y9IEx/PVbnIi1hYNyGCmIgxoJKPl+0ggaezWBof6TZ11+Xp91WnJ2D+/ymoxfmIeO2rN
         LpLrfQyqmws1w1c44i8yC77+0mtESFlHQAvVAJBxkOKoh3YAQF3krer5ze62AoADqVwd
         oSnw==
X-Gm-Message-State: AOAM531GWW6iSUzzLnmWwO5B6Ni1s54jW9E4SwSKi7/sYkhEW6LwERYi
	m5ZbQhihPP+zIbZuLPn7mtM=
X-Google-Smtp-Source: ABdhPJyShYRAsBtJRHKmRLcvGxaWJ40Rw51XtiPRmqlnqN8RWY8vnZTFutc/+kmR+NGajmKSeLWo9w==
X-Received: by 2002:a05:6830:12d6:: with SMTP id a22mr8052347otq.66.1621411808404;
        Wed, 19 May 2021 01:10:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:77d1:: with SMTP id w17ls3423884otl.5.gmail; Wed, 19 May
 2021 01:10:08 -0700 (PDT)
X-Received: by 2002:a9d:7a44:: with SMTP id z4mr7869823otm.196.1621411808025;
        Wed, 19 May 2021 01:10:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621411808; cv=none;
        d=google.com; s=arc-20160816;
        b=ymXPZHYBIPC6oVgqhdu1L07ll0xj2l5DvjRUoLF346r3Lo/nBB2JYOQzSpGBAG12N9
         8HMtJ4+V9pOrTmPGlFbVguJjZBr6cuQk8+sjIcIZ1MKaKTDs+tznk/W2/lI68hEOboBK
         Xw1AxJqi1O+FpRVPUQfAnp0n9PhTbrZtgLDrC+WNe9RGn2QzbWYgzbPLazbAk1qDhOl8
         oLLMDHay75FrE20xRJGwEbUMPs10GwWETvnN0qnzJ6kOv7Fu6aWy3KoSJmsp0IpkpF8f
         5qGOZYidXuYOyzEqxEb55G1XI77cPcvuzoIB/uDw5bmdBLOqS+5wPk5QdGQ3inXPpX/F
         X1wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U1m3QthGxvv1NLoiTwxWzLfeaQCVyf+o0wvQq3RcR54=;
        b=V1VOV4qi+Wn92zb9h++lBB/80v1sLuYA3Z8tR0v9JsoZUARfxPzTdlos9OW4eQ4GmU
         tPd8VU4xmsgr4F/1vJag/A66xcSo5gaTYrKyZ+JE9Zx1PyprHnkBh5Z5wWvo/UH1xESj
         Y9BmNfwEpdp6SnWHolrPmQZdDnZYxCyhtiJRGYLbYn/w1utmG2x392V0xSwj2S31g07Q
         hup70qBblyFRYItJ5FmfSOwNhNuJnwNjCD0tFEeZTFUZeaRJKsCd0OdiEQx9aqB5+O0I
         j64aADSduogli52FSrnkYRonBMXaHtmKM6UrBm40SuhEdt16os4jdP2EzrdeWUw+fnmL
         yekg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hsTBydpA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id w16si1650540oov.0.2021.05.19.01.10.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 01:10:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id v19-20020a0568301413b0290304f00e3d88so11056567otp.4
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 01:10:08 -0700 (PDT)
X-Received: by 2002:a05:6830:349b:: with SMTP id c27mr8184955otu.251.1621411807615;
 Wed, 19 May 2021 01:10:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210514140015.2944744-1-arnd@kernel.org> <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1> <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1> <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
 <YJ8BS9fs5qrtQIzg@elver.google.com> <20210515005550.GQ975577@paulmck-ThinkPad-P17-Gen-1>
 <20210518232012.GA2976391@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210518232012.GA2976391@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 May 2021 10:09:56 +0200
Message-ID: <CANpmjNNqonF82pzkmHnNmhPtoZfOihAooanVkt0WUFRaNdEkMg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Arnd Bergmann <arnd@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hsTBydpA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Wed, 19 May 2021 at 01:20, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> > If I have not sent the pull request for Arnd's fix by Wednesday, please
> > remind me.
>
> Except that I was slow getting Miguel Ojeda's Reviewed-by applied.
> I need to wait for -next to incorporate this change (hopefully by
> tomorrow, Pacific Time), and then test this.  With luck, I will send
> this Thursday, Pacific Time.

Thank you! If I don't see anything by end of this week, I'll do the
reminder then.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNqonF82pzkmHnNmhPtoZfOihAooanVkt0WUFRaNdEkMg%40mail.gmail.com.
