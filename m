Return-Path: <kasan-dev+bncBD66N3MZ6ALRBHV3RCBQMGQER3VJ6WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99F0C34D746
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:34:07 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id t5sf753167ual.20
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:34:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042846; cv=pass;
        d=google.com; s=arc-20160816;
        b=dO1VPQDemqjiOgp4VnClKJu0kizyJNSYUP+BVVJ+kr4bArivsaclhUnib3Way02qX3
         mRCXMSBFG75sbx8E0w4zrqjj8HWkWqpv0FlrphJb/75ODlOzz6Un1enZfFoiobU1RzDs
         BOopVZpDbfHdKefscTDhbh7RQT4eBx5OAd388tQpidyhqXVbFFyUDNSHxGuagTZEzvkl
         VTf9eCBNHXsGcMeDUavjsA0LyIPrhn5SqnB7y8rgn0mxbuaDsvqEWZM4FlMpKOzWF7Rh
         UrP/A71P6tWEU78CMWlUFpRKfZSFRvArPYY66GXoLiacrd5e5fPsl1GZCJf78NttGoQp
         1dNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=HnB2sQGv7C+qxg3hVQPreTOxG9auDManEBUs3mOfRd8=;
        b=oz8yy7rMTWk1tdzaGY2EvJpkDFrYHr802rInmF5Z9ZBuBfyLV8binNRJ1bU5G7XITG
         TWSz8hRApX5szZSGs/IPdGZLB/+v2VibXtfF+JeGUlQvwx/jpQSZH0/OWzRcJD01N8x0
         cN421y3vmOUWuJU9lHr+bdKbkWUiuOe5GKrrt3LC5qQPYkSLYyXFv3VQymYP19e/01oA
         2PvOUBSmQgVGFO/qjF1zSAy1VUvDA/TbLw2wjaPg7PhBMnZFxjQaBEpn5vjFLB68WCW6
         njkcZgbisQ5rkLphXsvnEUmgMDObhkcOoLAGl+8rqPOnNdIXeXPEC8MXtRwNRmickp3L
         9ubg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=b6999D+6;
       spf=pass (google.com: domain of oleg@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HnB2sQGv7C+qxg3hVQPreTOxG9auDManEBUs3mOfRd8=;
        b=fQamHFXYkeskPxLyK4Y8EMMC/qY9/7UIH6pPiixQKsHd/zFaHEiktjsOyLY0Ivxx9d
         SX1KZkBxPiqhDzIyAHZHiZ9+qM/R8+g44huXcFNVH2yOU343teBsdmIhDw+o1zNBvvNm
         7KyIndvs9cacQUQeOY+yfQ7ynck7xCSY1VRCHLN1eIaGz3XRcQ/nniO3iv8u7Lsq8r75
         /vI1tcjAUKWnt8kk7BkbwcGiniWu+MMVx0ciTpJF2+ncP7XaBgAKYqUn77Oevp1gzflb
         RilXyo1dApfJlBO9Jtse9YqJTv8onFyIiOeAVgwjfls72l7hzxwlbnTsHCA1sufqoJR8
         cZRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HnB2sQGv7C+qxg3hVQPreTOxG9auDManEBUs3mOfRd8=;
        b=DfnRPNtj/FbyWYl7mhKgFBGytGrRlOVanJaZZPNt5jiffvg6dpQXmZUq49Rrub+/nN
         RAv0q282QpVe8hlYBwYqgp+HheqyapNLBt2sC+FBDaaa/eHwrlviDTf2Nxkz3f+vAcPO
         NRkJj0D41qBBmjejJG4o0WJwUWge4GrZo6kB4PBSSU84hdBdSOXEV/XQbec7ymglsCv2
         7qz2FIwDDOJrvx5xvXT2ef8Hjglr8mUfZ3xyd0RgSqpwQBBBrdE5soLSl0tqJw++eom3
         GMmS6xM4c+oEuAMOeLgPHq/W93chbYxfEDMvoa0etN+oVmbamA/I2MoRGupqep92WKbx
         L/OQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LqhrZrI1f+mHIs+bQiB8RpS0Xpq497qENJeahUKJKW2iqkpo+
	qZn+FYsC5i+RM9RJWf9cpe0=
X-Google-Smtp-Source: ABdhPJzKTWiGb5Y6p4Yq2rTsQ2VzibdEdfy7ZCrZq3xFrIsd2X+Zj7fPB8jdOkAgsHA3xbKWBuFw0w==
X-Received: by 2002:ab0:7e99:: with SMTP id j25mr14228588uax.32.1617042846546;
        Mon, 29 Mar 2021 11:34:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c759:: with SMTP id b25ls465622vkn.4.gmail; Mon, 29 Mar
 2021 11:34:06 -0700 (PDT)
X-Received: by 2002:ac5:c7c2:: with SMTP id e2mr2455467vkn.25.1617042846038;
        Mon, 29 Mar 2021 11:34:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042846; cv=none;
        d=google.com; s=arc-20160816;
        b=A2x3lrSqxegp0eaoV+8J/V7KrERjFIEkZHJD9jf332V56UpznISElxCyXpH2h/Ao/T
         0VnPuzeWIcPO+Wgrg6xKmkwj5XWKiI8FacwaE8hsyJeQY1DfvQLhJfwohtDZWNNtgJae
         94Uf4CwTrNBEKIscx4Je8wNpodNH/OqTbQinRwb3uYcm2RK5QP4sAQP6IDS32w7mpICe
         79np4zUn7NkeOVV2ZbS+Xfovxo0NUrNk+Q1vjHgLFRmfv42T9y/EnR6Iao1juBkE7pQy
         fKaPF/xoMwCpc9ek8lzKl7ez0zeAGrkoDoVHxhlOrB55Aqn4tDoYU9o/Ur7IYOe4U9WO
         7ejg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pDaHHzh6SdLVte/qI+KKbIrazg9pPxb7giE0iRBcJy4=;
        b=IxtTCuQx7oJ7rD/Lye8ckQa+F3ow8lVla9o0c0dRBafqx3CkTBkQAPJubs8F2rWoAi
         U7dexw3D3qtFNevWY4jln0wIsM0c1B8QIXnWmu4KMAtxa4vq51X2CWEZJ8oIj3fsNAYV
         0T++CaouT8ROXThDL+KV86rqWoW/DP4iwzWsT0SPsdtNk807/ZOiEK0QgVmSgbrai77P
         gltLw0hF5OyhlOLhtKR2pyfZJYKAh4AewCMYWRe+CPgR9Wee/y515on0ddjGoya5jALq
         E4l7uz9F24OHn2Ts+Vca07/NsSyWvfGg87iRGTnsRBAKq+JxgxIvYYd8MvPPs10lVWPO
         yHtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=b6999D+6;
       spf=pass (google.com: domain of oleg@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id i8si1055856vko.4.2021.03.29.11.34.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 11:34:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-428-6CvGnPCoONa9AJSA2KRzUg-1; Mon, 29 Mar 2021 14:34:03 -0400
X-MC-Unique: 6CvGnPCoONa9AJSA2KRzUg-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 7C03F87A82A;
	Mon, 29 Mar 2021 18:34:00 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.40.193.79])
	by smtp.corp.redhat.com (Postfix) with SMTP id 4D0395D6A1;
	Mon, 29 Mar 2021 18:33:53 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon, 29 Mar 2021 20:34:00 +0200 (CEST)
Date: Mon, 29 Mar 2021 20:33:52 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Namhyung Kim <namhyung@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>,
	Christian Brauner <christian@brauner.io>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Ian Rogers <irogers@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
	Jiri Olsa <jolsa@kernel.org>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
Message-ID: <20210329183351.GD24849@redhat.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com>
 <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
 <20210329142705.GA24849@redhat.com>
 <CANpmjNN=dpMmanU1mzigUscZQ6_Bx6u4u5mS4Ukhy0PTiexgDA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN=dpMmanU1mzigUscZQ6_Bx6u4u5mS4Ukhy0PTiexgDA@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=b6999D+6;
       spf=pass (google.com: domain of oleg@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 03/29, Marco Elver wrote:
>
> So, per off-list discussion, it appears that I should ask to clarify:
> PF_EXISTING or PF_EXITING?

Aaaaaaah, sorry Marco.

PF_EXITING, of course.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210329183351.GD24849%40redhat.com.
