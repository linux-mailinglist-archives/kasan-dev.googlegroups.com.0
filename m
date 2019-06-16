Return-Path: <kasan-dev+bncBAABBIG3TDUAKGQEYE56C2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 92FA047466
	for <lists+kasan-dev@lfdr.de>; Sun, 16 Jun 2019 13:53:04 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id u2sf3361170wrr.3
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Jun 2019 04:53:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560685984; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZHnTCNHatRJ1erRaYWsmjwRCAF1Ln5re41wamz6KtPB9WA4nfKgQF6kwYgiGJMXMfI
         fDsBjliXOj5RY5bv7p724r+3TkVGZgfrucMhk8v4yCEN6idVbSc/FdWifF4RxdJ+1Yxv
         g4nl3PcCItjA9gP2+/Np3jnYOhgfxBWMJhxeZ4AddbssTeucSseFs8SCdobZDBxp5jR8
         +cr+F8bVRtaId2/6QukX3AzrT0qvVHr9rG8d8dHO625eZzllGLQserzhh2ruaLCdw/sE
         fNpX2PmBtxUFNIOkmEgm/deq0+j/QroTsSP8zYduqkfg9H+6yqaSWCZK1dfAfFV0fIQ6
         GSUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:organization:openpgp:from:cc:references:to:subject
         :sender:dkim-signature;
        bh=/jd312qLGYOGx1J3CB2y8bdEDOydGISXW5h626/AD78=;
        b=Y84hu9jCY4wF/yTsKRVIHSXsAOKul2Tl2zbVAtgetW8KJZN5B2d6siRpNi59rLZOD2
         WdTT4v4ugBrKvL4Q48wHUrD5yzzn6V/OeI+Rv3DS0vA5omsbDkETc5Vp8ahyzBn4PHF2
         ZtpBUVjnvo1lO2bwIH4fj0xjqhDZvY+3ykeXohBZTCxg1I75yM6w1F+jomGjYBpqAUa4
         M9D7oP0MzR4X1mbBTiV8juk3RthlMFVjA0feWL8mmOn+KlZilIQYQ9azB9WNpuxYsutS
         g46EGdO8evcZcbruMjGBboVzxZpHUnHGqONlLAHgT4+avtlC+3l0NnrHxtue8zg8QD7n
         jwsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of colyli@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=colyli@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:cc:from:openpgp:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/jd312qLGYOGx1J3CB2y8bdEDOydGISXW5h626/AD78=;
        b=mUIrtKVzv77jt2OCANVL1YqDHYaB3M3I/737s2jHNDC6wfwpZGH9yfF3scR7C20h9l
         cnQozbpnuBVMA75KuGgT2a/ATfdjt5yw609IVTYlQe52dOF3ZCWxGLyGrTzS6OBRPzlp
         hNefxM5caVw2ivKiUvBHrQ8GMLNqNTU1JmiLSjhOHats0s6gVle2+i9BWsVtPnubDe8O
         3FeQkURHyeGsMs9cizWd7NSsDfxayo7XUNQo7fHaQxqBpD8Dm/e2e3yaAfI/VYaFeCEo
         QWhyaN80Q2wbJ6RmOve7cWM2WASuMUPkrgrPl8O0a+1ZzikxYJLtD4ljOGDkWIOtFtoX
         e87A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:cc:from:openpgp
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/jd312qLGYOGx1J3CB2y8bdEDOydGISXW5h626/AD78=;
        b=FfIa+WX0uM/IS5tvSYTxv3hr6Yo1ewpJ4mLd2kUqFMTjlH5o5Md9LdsSwyyjh1HiOA
         58plEGvYKnWrhDYVDzTD6+KFIF7QRKndXHx8D19gQK/8tYAIAjAAtNIhazt9NFOSJ1Dx
         sojF+2OMtgd22xopfrIIuSjjKPbF+0rbDctRUP+gKx+GWRecU4/3xh3VR2pCosBvUMSM
         2l3GqpaN4LrflMlyPltyn0bRFMn9kK7PIG9SULFw6e0DqCeMvSwpCafe9Xmz7M1ONGhU
         +LbKDklXihn6awgrnsTTsAU+JoAcs/YgIvb6aPLWU4tmi9zjSToqYCHXZzTXJ1rCG8CX
         lWug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUAakoxzB4Nv4YVO1okLoRAuYADlYA1c5LdjsMg96DqrqGbz/zv
	m2blJ9w0U7Qwg4qtTn8Z/tU=
X-Google-Smtp-Source: APXvYqyeWLJgI5+XmpZVD9vUim1TXdnNax+FqWvI0vuCfafumu8gMxhAlIHdKFeuu1NamZ2LHLOuSA==
X-Received: by 2002:a7b:c933:: with SMTP id h19mr15536887wml.52.1560685984320;
        Sun, 16 Jun 2019 04:53:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5f86:: with SMTP id t128ls4076506wmb.3.canary-gmail;
 Sun, 16 Jun 2019 04:53:04 -0700 (PDT)
X-Received: by 2002:a1c:eb0a:: with SMTP id j10mr16017591wmh.1.1560685984033;
        Sun, 16 Jun 2019 04:53:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560685984; cv=none;
        d=google.com; s=arc-20160816;
        b=L33dv0+w25XunocAEgB8a+JKE3qzIBzh0x1uMVXxbU5ftLgO0VM5LULYhB/Kcx+eUZ
         ryeRkg9ZmV45wmAZFZZtYzV+6wrfkvyPwhMKcnXnlDpitlRsZZ3U2J//NBrmIw8rrUS6
         g6K8LYEJ4dpaKDYDL/arL/yBgpY74+hYSO0G3+L+Z/M5/T/norikqkl4uxok8ecKBq2l
         W/03abzZq+MYuuLocD170LPqdlbjnxbuU44wrt724Enb9HCwjNWuA0TW7uWXRBYcBIWB
         PvN2RNz9Hc8Lk3p1h+qMGaMFUCyDgSODKhlTnc7MaJCD1aOS1wSP1nyxjZhMV4ZKu3qf
         5PzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:openpgp:from:cc:references
         :to:subject;
        bh=bqm7Crc7T/xka7RURYv9moYimgLFvKiO4hOMO5RsQF8=;
        b=UYO4zYqyzAoDHAu4CEHQ8QIlvBDZIuUbsDixtczrVtrkh+NfsZhQDhleB/JeSmGBbf
         wfLUzXkm0FukUQbv2wSuMayhYpZpVRneDPqUWJLJMIDziIio0zUlZ1NNF7Qw1mO+0Uti
         wJYFzjQjMo9fW/5s2QuL26+OCBASUJdk2jIMS6F47IIEC50AmDiLpl9rCDKrWKmg6sBv
         e/76edBE3/cqe/WxErVr553vx5p1K4+MLmcdlmEBnkN9Ir9T7TGrSi14Af7Fow/3Y8zW
         S5KaHWKmQuqj6Vxb0tI9/giaJhNCSDEZyo9hWpVq341HQrJTfmdbgxgbN2aFZZzLF919
         2Wsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of colyli@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=colyli@suse.de
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id j15si224522wmh.0.2019.06.16.04.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 16 Jun 2019 04:53:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of colyli@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 08217AEF9;
	Sun, 16 Jun 2019 11:53:03 +0000 (UTC)
Subject: Re: [PATCH 0/2] bcache: two emergent fixes for Linux v5.2-rc5
 (use-after-scope)
To: Dmitry Vyukov <dvyukov@google.com>
References: <CACT4Y+bgr4aC-DZuLCyhxpcES39mbEgLV_UWakmkOYEBPrOkwg@mail.gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 linux-block <linux-block@vger.kernel.org>, Rolf Fokkens
 <rolf@rolffokkens.nl>, Pierre JUHEN <pierre.juhen@orange.fr>,
 Shenghui Wang <shhuiw@foxmail.com>,
 Kent Overstreet <kent.overstreet@gmail.com>, Nix <nix@esperi.org.uk>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will.deacon@arm.com>
From: Coly Li <colyli@suse.de>
Openpgp: preference=signencrypt
Organization: SUSE Labs
Message-ID: <1c976ca8-6ba6-d27a-3fb0-3f77d7dfc523@suse.de>
Date: Sun, 16 Jun 2019 19:52:55 +0800
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:60.0)
 Gecko/20100101 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+bgr4aC-DZuLCyhxpcES39mbEgLV_UWakmkOYEBPrOkwg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: colyli@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of colyli@suse.de designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=colyli@suse.de
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

On 2019/6/16 6:23 =E4=B8=8B=E5=8D=88, Dmitry Vyukov wrote:
> Hi,
>=20
> This is regarding the subj patch:
> https://bugzilla.kernel.org/show_bug.cgi?id=3D203573
> https://www.spinics.net/lists/linux-bcache/msg07474.html
> (don't see a way to reply to the patch)
>=20
> This looks like a serious bug that would have been caught by
> use-after-scope mode in KASAN given any coverage of the involved code
> (i.e. any tests that executes the function once) if I am reading this
> correctly.
> But use-after-scope detection was removed in:
> 7771bdbbfd3d kasan: remove use after scope bugs detection.
> because it does not catch enough bugs.
> Hard to say if this bug is enough rationale to bring use-after-scope
> back, but it is a data point. FWIW this bug would have been detected
> during patch testing with no debugging required.
>=20

Hi Dmitry,

I although thought it should be reported by compiler, but no idea why
compiler didn't complain.

Anyway, since now I start to enable KASAN in my testing.

Thanks.

--=20

Coly Li

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1c976ca8-6ba6-d27a-3fb0-3f77d7dfc523%40suse.de.
For more options, visit https://groups.google.com/d/optout.
