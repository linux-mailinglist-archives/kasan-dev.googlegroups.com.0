Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFOYGNAMGQEI6BCQBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 77C3B6050EE
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 22:00:13 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id h21-20020a2ea495000000b0026dffd0733asf7600442lji.7
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 13:00:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666209612; cv=pass;
        d=google.com; s=arc-20160816;
        b=Id+kRxDBOG5W3aEwyTIo4vRpaWRep03sb+nQ/scWk0W24zS6fV1ndpBv7yBzBBzZho
         z7ihVwv8yOccmahuJ6qmVZlQfApiRSaw0Mmp9qedspsFjJyMjJ22UL8BRNl4nVxzOIKF
         eYbsbAibVBeegsewpv5y1kXuKni+eNZxVEPzJ/vckUt52gCwIEmwpuV8sRw/LsA0rL+g
         20yXQXgxMPbQJTpm4IzZKxycbQyyvb6j7Dnt89umqRa3suQnhyc1zEfQwcTAOulZ/K7w
         UGbiE7IOgzK+ftFr4vbsF3FcGOMgr0W12HmrK6hxlIbMnqLGwzsPWU4vbFHWsjLgeYUF
         2iqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/HGGvk8gpxKEw+0umMfGBgbczBCL29sP4VLb1dQaGAk=;
        b=CzlRJO7aT0AQfkfzvxSQr666u2mBdKLiUaRIR2wZiaXa2ZXGgef66j2Od6VYPxZujf
         mugkh6yQ1Pk4TbALa/v3ND+tSoKhPdvhR9d24keSTEyrEWCR62AMovvMEapsbK/wOQlN
         feRg2F6pGozc0gjcBwlNwqQ/CPQkl3T9EEcr5lBGAYjP1mEXy2uk0Pci5ph6CgSrxGmE
         fzPp6C+SyBzNxeiE88Doj296oP2Bnv/yCQVK5OosZuYwhepIyfTrz2kRivy3k/7W3GiT
         g+0CZUTcrEXNOSUyRkTfYLISWEsjgAWqoS6ZAuM4ykmu9qY3YFM4p2DaglZTqEeUpIDw
         PKFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lw4jVYTI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/HGGvk8gpxKEw+0umMfGBgbczBCL29sP4VLb1dQaGAk=;
        b=jB+9TffL2MTSdIkbrXOdidmFqEAdTp+sNKNccliKk7qfdWM3x/zWk3N+3CAdZhiQyF
         gL6EK2M5QkWxf4nNBfpxYtbpYOUMke7ChcOfRHQ64HWC4bzebXkNBcz8wMNtKT0UAj7O
         32tSZb5Oryy3LoOs6D1Oxzi94RsKKr9Ft5bYOyQHG5b4EhEKFWPSoalonBoW8XppcHMC
         o+RUKBApEQpl69zKP0kM3UFEbiYPfQMtD+akutnNyGeII39sBQUKor1ZJHcn+qzGMqWu
         DSiH8e6n5wOkGOevO0ZYpqIGEJ3DnJ3UTXtXBBXcIWeYzXZJt74V4XNyKRm8iccV5vV9
         QbrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/HGGvk8gpxKEw+0umMfGBgbczBCL29sP4VLb1dQaGAk=;
        b=WysZw8iOxOvNwQrPcMd6eE1WxeP01lWkOG9k9Adu2ADC9a0FcqDuT9+3ZYb6Go06yg
         1bxEUvqqAEIOaDtLyGyl6P6LhhOFbUaGq0ju19nH6RbbZiU8+G2kfae8tpJ6RN/MoygH
         pexh2bz4Yx8HB7vREJHWG1mc7tS1htAALoFlhfMbiaUJ7c+HGFkPRqXCadFgFJU/6hKQ
         1b1ACltKGItPgoCgwZFI5+YJfSWvNfRyyCnAWiUFhXXKYVy4HiPh85IcSnmEoUd0KyO1
         7UFqTdkSCNAQNYp6qXzh1RvMjMu/I7jovcK8/2QX/nzUG3ky+NNfWTIWAZrO6UN50SCm
         J93Q==
X-Gm-Message-State: ACrzQf1WVeZxvuIHijbKSdtftkF/59YZyuAsAciT2ctvQFRkBt8ZjCfm
	gNwoBt9lMjhThYtlI3LTK5M=
X-Google-Smtp-Source: AMsMyM4G6WDEfa7l6LyYM6fGWne7W0R/Smr+49v2q3XZahwH1crAS+qiwwYjuej4W0Vap3UYmx1o+Q==
X-Received: by 2002:a05:651c:1505:b0:26f:b4a2:49b3 with SMTP id e5-20020a05651c150500b0026fb4a249b3mr3453776ljf.443.1666209612464;
        Wed, 19 Oct 2022 13:00:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f5a:0:b0:48b:2227:7787 with SMTP id 26-20020ac25f5a000000b0048b22277787ls4592659lfz.3.-pod-prod-gmail;
 Wed, 19 Oct 2022 13:00:11 -0700 (PDT)
X-Received: by 2002:ac2:4c03:0:b0:4a2:2273:89c6 with SMTP id t3-20020ac24c03000000b004a2227389c6mr3141490lfq.245.1666209610963;
        Wed, 19 Oct 2022 13:00:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666209610; cv=none;
        d=google.com; s=arc-20160816;
        b=B1ZsHuMNvBsUNmvYP8BSb7EsXE4u2ulh8qERlPPQYjlkbc2Jm7yW3HgcHQ05m59IF4
         CByhJm91ZmHxLrxMn2ad0qLCx9YVKqJT2kVSrgPR1ENlIMDI58F0TDh3PvUiVQPBqY6+
         JuM71DDhxbGunzNa5ooj+QTBdw3Y931g2cntB8kdbtFjPIlTI3zKXYk/M4IE4E/pZpuJ
         V7AtBCDeLNzLGESyMA21zDpdo3iBKSFyAv3D9w9VkEFtRW5pTdt/MRjPMRnYPW4u2i/G
         vZGkvUvBJ3AL5DkK2oQeE3N496QIJg3gv+/Qc1+2YKRaZutpECMFElwuPaVT94MvDRI+
         GWVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Y2N+V1uC9FDjbZcJb9aKbA76091h0TpDZZKWHaAmAek=;
        b=sUMl53cMLkxWWBzxHstGxyXzyRXPr/FvUo+RiVsmlMLCHyuD0549rY+sCP2ps3teqg
         xTpLZway8/5VEqZJTQEIMuoAUDfqiEF2vw+7FBJy2zVxqrkIz9DX/1Q9OPj1JXj03GHR
         Clpyfany9ZaA0v2fzW8BY9bdJqCKvEDGSx26QIa53fP648XDBg7cWeUc0DC9v6GYaIQm
         RyK2yGfQON/d/47RcF+VtM7MkE4+yl+7pJcrC1c2wgWtlpU8WBMj7fi6Vx5C2cw61udA
         Bvi3h/oF3nr4Iz9gXvhp/PrIGUdoPbtnfkTPgV9apT/isaIFghxlucQdZs4F9F9TqgHx
         Pmsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lw4jVYTI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id p11-20020a2eb10b000000b0026dee3f71aesi589393ljl.5.2022.10.19.13.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 13:00:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id c3-20020a1c3503000000b003bd21e3dd7aso811190wma.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 13:00:10 -0700 (PDT)
X-Received: by 2002:a05:600c:a45:b0:3bc:c676:a573 with SMTP id c5-20020a05600c0a4500b003bcc676a573mr28289654wmq.118.1666209610271;
        Wed, 19 Oct 2022 13:00:10 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:b751:df72:2e0f:684c])
        by smtp.gmail.com with ESMTPSA id ay18-20020a5d6f12000000b0022e62529888sm945871wrb.67.2022.10.19.13.00.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Oct 2022 13:00:09 -0700 (PDT)
Date: Wed, 19 Oct 2022 22:00:02 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: youling 257 <youling257@gmail.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Biggers <ebiggers@kernel.org>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
Message-ID: <Y1BXQlu+JOoJi6Yk@elver.google.com>
References: <20220915150417.722975-19-glider@google.com>
 <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Lw4jVYTI;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Thu, Oct 20, 2022 at 03:29AM +0800, youling 257 wrote:
[...]
> > What arch?
> > If x86, can you try to revert only the change to
> > instrument_get_user()? (I wonder if the u64 conversion is causing
> > issues.)
> >
> arch x86, this's my revert,
> https://github.com/youling257/android-mainline/commit/401cbfa61cbfc20c87a5be8e2dda68ac5702389f
> i tried different revert, have to remove kmsan_copy_to_user.

There you reverted only instrument_put_user() - does it fix the issue?

If not, can you try only something like this (only revert
instrument_get_user()):

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 501fa8486749..dbe3ec38d0e6 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -167,9 +167,6 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
  */
 #define instrument_get_user(to)				\
 ({							\
-	u64 __tmp = (u64)(to);				\
-	kmsan_unpoison_memory(&__tmp, sizeof(__tmp));	\
-	to = __tmp;					\
 })
 

Once we know which one of these is the issue, we can figure out a proper
fix.

Thanks,

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1BXQlu%2BJOoJi6Yk%40elver.google.com.
