Return-Path: <kasan-dev+bncBDEKVJM7XAHRBEWBRKRAMGQETZAXLUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E01A86EAD44
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 16:41:23 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1a6a747efb9sf23856715ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 07:41:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682088082; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQmjKOZ6b4Mactld4cKny6IURcmMOshewpvwrLvQkdeAFbcJdy4oUIiulpAVHH7d3k
         uAy7HGqDAEOTnn4JExOBUuCK43l/I4l5WHAp8+7C/X6IT2KCLz3acZlJbKFv2miC+Fbj
         LNY+G4muObRulHn73/X2sm1fgo5+YEIwtw28LJWk8uW1Kb+d4oJoi9QPPyXrsTryP7n1
         EH15ArhapiYpQL9ELvXNO7pMnZiBkLIFmW7SaMu8HAjjuOITysu+zVDyXpXI6IdEcS/q
         EuLL9cGLr8Ro+uacIej0ybt0C8nUpXL3h4kgZwcgIhPzY43gM/ahvymYnd1P71AyRjDj
         DqFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=pd38snFeisGOffuQkM0faFocEVQdRMsXrtchwg9RTJg=;
        b=JRuNwU88P5wkLi7ewEaFvzML2PJc9lvqoIquRONBjbTzBBVMxKbj1z+SXvA1LOADZh
         nb4eMSLHp2XLX7x2ZGc+nO67xh72flGqlw5gpm7QLONQffdN+LnM/gIEccTFReAbnTgm
         ts8w4reAmLzGN3g+zxdH1Qdpu/ppTdrY7CLLS3F1vqeq1SlxKnwDdyy+fjEWHZcglxAi
         o+7i8PeES0lBokJzV7YQKGYL7YGBDEuYJO34qmpElDAZRlBvcMhayS07v7TDe/LbWmxG
         uQALeKSQw24U11rVKu3pOXDTwfqcvzEVYmiKrQhu8BTop+Pd8Th2JBoDgt+to5OnJsh3
         iuZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=akb4FBXO;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=G6XCCAdL;
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682088082; x=1684680082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pd38snFeisGOffuQkM0faFocEVQdRMsXrtchwg9RTJg=;
        b=bhSB6UVgLbZuUbxQTjaNUCrIoIV36HhQtLK+yB+PsF9dx7y2ErlO4qC40qjo5leNis
         SKm+UtLn8oThaBXxJy6L8kIsAz3JxlSZOoqaBfdHrgOueT+xZh/q6pqxH2Q/MfM0OMuX
         jaKs0yqGNmGMffZqASzwPRqWGmENDIx5Rvk90Y1FzXdlgeSLab0kFDZ4ECIsciyD6KGf
         hjtABU2wj0n3c/SLJDL2WgQ28TUSWuR9ZKf3La/VAl0+/saroiDPkW2jvRYaZpkqgQAd
         MreVJU7Nl+oRO67NNXLCc5urXLnZHGHmLRRqU6rIW2Ew+FleOhTQY5D1ofmK+JnnsUKR
         9t2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682088082; x=1684680082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pd38snFeisGOffuQkM0faFocEVQdRMsXrtchwg9RTJg=;
        b=EDP+cjUs9XY6N8iDofMSNwP6NNr605zfGhGBkjAVvtveBMIS5rNCLW/wZIcMo+BalO
         YmJyiIO2vvrGokNdQMNg8hI798rGoxY3qGnDJyJuv75KynZcRuRgQDX73az7SO3PlF4n
         94FkPh8AGCDv72GhAuewERMssLTm9xwtaYtpQAME3F6l3b9LLBuQtmxmvNlz7ihxjUAl
         CcNxzKxaHfYvEjU5oPhkUN7cl980xBCkNEaSA4vdRejyR3k//IUSUMKJ+bYSWfB8F7OM
         KB5gVPKlWNDW762FiXG3hXxdAZqC4jm39N36aHw3POlEIwnWzToMG4txncX6IG4mtGuw
         ap9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eeayi+hRjocbZZUiSxRrIh62m904SEwuz4qpuAWsxw77PZweBL
	LL0yXEFDHLTLoL24/8YJ19U=
X-Google-Smtp-Source: AKy350Za/XVVmryf8lqjtl89ioay+FQbXAGf8thi0fhsb8SWfOTH4BuZlglpwodJ6ubtJKMpbjCDDA==
X-Received: by 2002:a17:902:8543:b0:1a1:ffc0:8b9e with SMTP id d3-20020a170902854300b001a1ffc08b9emr1837677plo.4.1682088082264;
        Fri, 21 Apr 2023 07:41:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c793:b0:1a0:482d:27cc with SMTP id
 w19-20020a170902c79300b001a0482d27ccls5020014pla.3.-pod-prod-gmail; Fri, 21
 Apr 2023 07:41:21 -0700 (PDT)
X-Received: by 2002:a17:903:188:b0:19f:3797:d8de with SMTP id z8-20020a170903018800b0019f3797d8demr6646437plg.9.1682088081497;
        Fri, 21 Apr 2023 07:41:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682088081; cv=none;
        d=google.com; s=arc-20160816;
        b=QeIelxTBRq0+y517evGXfu22WoQl8EVegnw5FlGhitUgA2Fl9TKQfCzMtkQJ5TtbdH
         fv6M6mjGzV/xtvdg2J8Eq285iFo/73I2WScFfIvqdnJ84WCtO7896VAO2rhR63AQdTS7
         Lb9GmevYEEMrFrMReTIifhTITMO9EEAPa7pgTBbhMBjKX/bDcq/tZR2OrbO9ncZ1lKLJ
         7JAAWXX9etxTnFn0oVwBuqy5MNnBuFW2LVjuM1HXVZ3JJ+RM+4k09AQKRGFnAjsyR8Ik
         sCZOcf8ad0XSyMFYweU4HLR48/e/vHBqz6kqHNu+5ueZDNQ+ofXxifC1ws0winjccLyR
         dmtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=cqrMn8PsCijMPIlumhaZUxmJD7Z0ZbjGhB78P+4Vmns=;
        b=QQ2szWjQhhzfdPshQuKfJ/bgRc7sH+mPKGmRLIGiZ5JawCcsYmVIcV98MMUH4FFbEK
         ah8q1y/J6sJhQLBwTna7HwCH/wzVHE8ThxXSAneliwYVz1pPMsLLrp8vqX7G1XDBY/na
         X+q6FhiJQZroneTNRVAhCv5YuJ4YahwX8tXdyBbtoN82zzlv8Co8jD24ZzD/Q3kuuN3x
         N6t+KsNU1QtPSCxnzN4RCPQG4yy3F9XFfIvtWywlim+sfp/59PV3OBzO+LBcjZmoOBEq
         Y3MrZTVQEPMQwS57F5CmQlqRAzJ30zMxaafd5/b/N9UF+XJ9oidvPMdBC9UBBFcX8EUQ
         HDYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=akb4FBXO;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=G6XCCAdL;
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from out4-smtp.messagingengine.com (out4-smtp.messagingengine.com. [66.111.4.28])
        by gmr-mx.google.com with ESMTPS id w13-20020a170902e88d00b001a69a20f22esi170694plg.11.2023.04.21.07.41.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Apr 2023 07:41:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted sender) client-ip=66.111.4.28;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.nyi.internal (Postfix) with ESMTP id 960845C00EF;
	Fri, 21 Apr 2023 10:41:20 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Fri, 21 Apr 2023 10:41:20 -0400
X-ME-Sender: <xms:j6BCZOsa_vcrg-klHnDAS24LMkOJfstwHLKUZp5Sc_0WnM_v21c1FA>
    <xme:j6BCZDe0-sURzRSMs48FAYJt2IMmBl-YlgX4Im-OI4Ly7y83mjtVjmWa9PUK-a_ct
    NhuS95AYe8cWs87Qi0>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrfedtgedgjeekucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepffehueegteeihfegtefhjefgtdeugfegjeelheejueethfefgeeghfektdek
    teffnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomheprg
    hrnhgusegrrhhnuggsrdguvg
X-ME-Proxy: <xmx:j6BCZJx9vFXii8uwxjpIhySx1T1hEPzDeM13BkBZwYOQu-2Nhv0y2w>
    <xmx:j6BCZJMPzzIOwy5n8y9avjpJjDd33ArN_5qThyCmZXTtmAR0mLULnw>
    <xmx:j6BCZO9377vt3-2-ZWeBVDc_O37hp3A3OSEMu6Lu6ZWeu_tEQoiNdg>
    <xmx:kKBCZB14XANXgKyXbeDmBwaEYhqwP0lAxDk4H8OAgRXMzQm8F8PoPQ>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id C7BB7B60086; Fri, 21 Apr 2023 10:41:19 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-372-g43825cb665-fm-20230411.003-g43825cb6
Mime-Version: 1.0
Message-Id: <e033ac24-0301-4c7f-8928-b940454c0a2b@app.fastmail.com>
In-Reply-To: <CANpmjNMRQiPPqifLbzob6OjOX9O+bWhGrQunZY+TY6gj9HwGug@mail.gmail.com>
References: <20230421082026.2115712-1-arnd@kernel.org>
 <CANpmjNMRQiPPqifLbzob6OjOX9O+bWhGrQunZY+TY6gj9HwGug@mail.gmail.com>
Date: Fri, 21 Apr 2023 16:40:33 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Marco Elver" <elver@google.com>, "Arnd Bergmann" <arnd@kernel.org>
Cc: "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Catalin Marinas" <catalin.marinas@arm.com>, "Will Deacon" <will@kernel.org>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Mark Rutland" <mark.rutland@arm.com>, "Kees Cook" <keescook@chromium.org>,
 "Ard Biesheuvel" <ardb@kernel.org>, "Marc Zyngier" <maz@kernel.org>,
 "Matthew Wilcox" <willy@infradead.org>, "Vlastimil Babka" <vbabka@suse.cz>,
 "Peter Zijlstra" <peterz@infradead.org>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH] kasan: use internal prototypes matching gcc-13 builtins
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm2 header.b=akb4FBXO;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=G6XCCAdL;       spf=pass
 (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Fri, Apr 21, 2023, at 11:19, Marco Elver wrote:
>
> Does it work with Clang?

I tested successfully with clang-16, but did not try other versions so far.

> I don't mind either way, but the custom kasan_size_t change seems to
> just be needed to workaround the subtle inconsistency in type
> definition, but in reality there should never be a problem. I'd rather
> the KASAN code just uses normal kernel types and we just make the
> compiler be quiet about it.

Let me double-check, I think I may have made a mistake here, and
using the normal ssize_t (but not size_t) just works right. It looks
like I confused the size_t definition with something else, so this
hack may not be needed after all. I've changed it again now and will
give it another overnight test run on the randconfig setup.

> To do that, another option is -Wno-builtin-declaration-mismatch for
> mm/kasan/ which just shuts up the compiler, and allows us to keep the
> code as-is. Does it have any downsides?

I think the warning is useful in principle, at least it makes it
more likely to catch bugs if the prototypes ever change, and to
validate that things like __asan_allocas_unpoison() that I mentioned
are actually intentional.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e033ac24-0301-4c7f-8928-b940454c0a2b%40app.fastmail.com.
