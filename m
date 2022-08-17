Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBXND6SLQMGQE54TLKKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C33259737F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 18:05:50 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id ho13-20020a1709070e8d00b00730a655e173sf3111727ejc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 09:05:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660752349; cv=pass;
        d=google.com; s=arc-20160816;
        b=YoDZuQfZGQO1UqELdfF0lWUaafoWXwmssamsu8q30msbuMADSvr3fRcE5CA6A+GDZo
         Oq+oPLub/r39GNr0T/EWBHuwaGRrh+sx3kwuPGcELxAyA1+u/DVlM42AACnIcWBz6saK
         1bQUMWB50wR9JPHYM/K+NswVqqKtXB1jIq6ffxjPB5SxPVwp6ilpUUAqguB1Co3gsAn8
         1zzIittpTNrH7ETYBejFee+hQomqbw0Lbc3lVQCgKaJ33mOjrgLS2e/hPImpbtTwMQD2
         j+92+ifEfyBtvALTGsxjFoIoEsx+kHr7xR/hOTCgTa6uoZVv9kU/fKRS8+0SY0x6Hmgw
         UgcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=2TltISCf7ADItc7F5GamPxZgBn6CfqHgo2zpO/cYuEU=;
        b=Mr5k9o62B/XKO+mqZmgCrrZyRJBZqkC5yDnBK1wyNJGIAE49uuod53o+ao02m6hF8w
         6X9Nj2YCUteH9W4GUY1ZHzZ1HtIdw1jT4svke2zOqo4WQMowOROBuXHdMpa1ZLb/Hwi7
         ydNmP0ajBdL6kdHgMTkO++BH8J9Xxj/lZT6EOipGTSFkuV11/5Z0QA88QkisK/vALY3e
         G0snQFFVFuEz3mtNAFIaykruBxVHXYKJKPVyZ1Jy8p+f3AgPq+HdtrF1KtEXVR9sDt6q
         J9/J/nOzLeieRpT+RdAp7JxLI1HFhWUYaY+hjBSM2YAC5CHEH6vTL6y4aLkOb6y+XoYL
         JuNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="DAPJSc/u";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc;
        bh=2TltISCf7ADItc7F5GamPxZgBn6CfqHgo2zpO/cYuEU=;
        b=P03lVZAiOUBVEPKljwAfeVylNQMw7r9nOtaQFCDmzczf5moqm3av56XP4tbK6fTMbg
         1/+OmOKHmPXvto2eol2F/8O7rkkxgRBuB2KKPUpdmlGcXyF0UgtCWJlFXuaZR0Bk4fbY
         uIO4gSJJ8mRTQOMqHd8BYveNwV2l+ki0QSDaHSkLe7G8O0U4cGgBcGWGuWmXfDG394Uh
         9sTAPiYJilg9JEQtz6Arm/Acc2xpxmWG0cMt+cp9HnQBRJ4bRe95BbdEJgs13EkNaTiA
         GpbAGYgAWZcRH3EAYElK9vkMK71vb55QtyN9iIkgwZn4gjtDvnrvWaDdbdob5He5PzNB
         vxwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=2TltISCf7ADItc7F5GamPxZgBn6CfqHgo2zpO/cYuEU=;
        b=EcOcuyYns45PrGVjQ7iXN+6TINxadTH4A2qL9+dOm5LUx1Ru+9YMp36sYcGZTtZv2n
         5c2+XurhcIZHo/I6nGnRv65P+XWhj50h4AsgULiLRjLw+HlkgCPaH8EldxZJGW6eUpND
         jUsXky5WSiSgMXouDptcK+THhu26OXRePezjP8nhbQBHZ3a+0XCCbszgAnO9BeSgLOhT
         WFeNchONJPpp2nWr21d6Lz1GvYQNcVGkqTN2JvnXoKY9LT0m57++W6mb3e+sMNnYKuOg
         +t0bqUF+zhChDMqwyKlJXu9ArECCJJzzwirO5tc/wiOa2L90AQSSQcp0DCjQK0Nf9LyP
         yy/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3lJj52pdnbucO7D6F4s+5Y+GAGJ5vWrf7OVoQatLcM6JjRwr/f
	ZEzV0vp74YqDUCiu0DzE8Oc=
X-Google-Smtp-Source: AA6agR5DfR0Z/6nqdRhIZAC2TItxI9v/Wne6+vgCkPDlTtXRLmw7YAfX+YJIxE9hpSHAOCWdE2I5GQ==
X-Received: by 2002:a17:907:3e03:b0:722:e694:438 with SMTP id hp3-20020a1709073e0300b00722e6940438mr17503544ejc.755.1660752349730;
        Wed, 17 Aug 2022 09:05:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4390:b0:43a:77a6:b0d with SMTP id
 o16-20020a056402439000b0043a77a60b0dls82130edc.3.-pod-prod-gmail; Wed, 17 Aug
 2022 09:05:48 -0700 (PDT)
X-Received: by 2002:a05:6402:369:b0:445:d379:d233 with SMTP id s9-20020a056402036900b00445d379d233mr3844000edw.395.1660752348417;
        Wed, 17 Aug 2022 09:05:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660752348; cv=none;
        d=google.com; s=arc-20160816;
        b=GUq3zDoTFbFRvGHb/CKHCnwdZH6fAx6LLBVxgVHuktggt4kU81CBgbLmfwRnK1qbYg
         bMjr6Foq4orouRlRixT3FUbGTvUjPKpNUHAvZ+tforzVzT6bRcs/uc1YxuxfniEt3aD7
         AmkGn4yORj0LhAWEkWbGAewK5FirGnEw6wdXsGtqPUuItCuGnAHkS5LcnsyNPxWuEJd2
         IvBf9KX82SMpgR/plKzZu7T/A7UfHryUyzUJhlKdcwA/JOdB0OVmdqsmTP4WkFGVL2Te
         FYI3ngT49T1u4Mm5SBV3USXGeRqnfGLkBWEyc5xvElR8kZ5FVEpkbhMrdkMPuz/RcWGA
         Yh6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U5jw3QHa+iaIPk1CEpZnETysV2acYZOZO5IcpVoLmmM=;
        b=jFR4sFzG4vBHItGe65gtHSx/+j1/qzHRcBSgOcHtL8ZQMgWm5B4/RCv6EdwZmMfIEq
         DTgNv45NGpalOd4CtzfPUKWDgQpl+H3s/7mb4XiqIUdg77jVPv/C/CIUc4sWg+8uLnQ9
         XNmjUWUQnDlstJqhE0gnFw2v7gQIlPXSlMUrWAZxtkeEHjf6Rg6Bmwt+ydmb3vXN8kiM
         c38iLsuNmcfMjfrLXN5KjmX2MhWrpc1rvOGieOoq75w7pYrqU4HVZnWL2Twpzer6JNba
         g5fpN/MXSBBpQsRWddycC3ZZJoLez2fudHZqFPgiAPSubpw53QhDOGlo8XGo6dMFcjI+
         C28g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="DAPJSc/u";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id bo20-20020a0564020b3400b0043c90c086d5si1036044edb.3.2022.08.17.09.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Aug 2022 09:05:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id f22so18084854edc.7
        for <kasan-dev@googlegroups.com>; Wed, 17 Aug 2022 09:05:48 -0700 (PDT)
X-Received: by 2002:aa7:dc10:0:b0:440:b446:c0cc with SMTP id b16-20020aa7dc10000000b00440b446c0ccmr23789625edu.34.1660752348025;
        Wed, 17 Aug 2022 09:05:48 -0700 (PDT)
Received: from mail-wm1-f42.google.com (mail-wm1-f42.google.com. [209.85.128.42])
        by smtp.gmail.com with ESMTPSA id n24-20020a17090625d800b0072ee7b51d9asm6962211ejb.39.2022.08.17.09.05.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Aug 2022 09:05:47 -0700 (PDT)
Received: by mail-wm1-f42.google.com with SMTP id h204-20020a1c21d5000000b003a5b467c3abso1234198wmh.5
        for <kasan-dev@googlegroups.com>; Wed, 17 Aug 2022 09:05:47 -0700 (PDT)
X-Received: by 2002:a05:600c:2195:b0:3a6:b3c:c100 with SMTP id
 e21-20020a05600c219500b003a60b3cc100mr2523659wme.8.1660751916369; Wed, 17 Aug
 2022 08:58:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220815113729-mutt-send-email-mst@kernel.org>
 <20220815164503.jsoezxcm6q4u2b6j@awork3.anarazel.de> <20220815124748-mutt-send-email-mst@kernel.org>
 <20220815174617.z4chnftzcbv6frqr@awork3.anarazel.de> <20220815161423-mutt-send-email-mst@kernel.org>
 <20220815205330.m54g7vcs77r6owd6@awork3.anarazel.de> <20220815170444-mutt-send-email-mst@kernel.org>
 <20220817061359.200970-1-dvyukov@google.com> <1660718191.3631961-1-xuanzhuo@linux.alibaba.com>
In-Reply-To: <1660718191.3631961-1-xuanzhuo@linux.alibaba.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Wed, 17 Aug 2022 08:58:20 -0700
X-Gmail-Original-Message-ID: <CAHk-=wghjyi5cyDY96m4LtQ_i8Rdgt9Rsmd028XoU6RU=bsy_w@mail.gmail.com>
Message-ID: <CAHk-=wghjyi5cyDY96m4LtQ_i8Rdgt9Rsmd028XoU6RU=bsy_w@mail.gmail.com>
Subject: Re: upstream kernel crashes
To: Xuan Zhuo <xuanzhuo@linux.alibaba.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, James.Bottomley@hansenpartnership.com, 
	andres@anarazel.de, axboe@kernel.dk, c@redhat.com, davem@davemloft.net, 
	edumazet@google.com, gregkh@linuxfoundation.org, jasowang@redhat.com, 
	kuba@kernel.org, linux-kernel@vger.kernel.org, linux@roeck-us.net, 
	martin.petersen@oracle.com, netdev@vger.kernel.org, pabeni@redhat.com, 
	virtualization@lists.linux-foundation.org, kasan-dev@googlegroups.com, 
	mst@redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b="DAPJSc/u";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Tue, Aug 16, 2022 at 11:47 PM Xuan Zhuo <xuanzhuo@linux.alibaba.com> wrote:
>
> +       BUG_ON(num != virtqueue_get_vring_size(vq));
> +

Please, no more BUG_ON.

Add a WARN_ON_ONCE() and return an  error.

           Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwghjyi5cyDY96m4LtQ_i8Rdgt9Rsmd028XoU6RU%3Dbsy_w%40mail.gmail.com.
