Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3PP2SZQMGQE3YPRPSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id B8E75911E71
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 10:21:02 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5bdab2e0eb1sf1834267eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 01:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718958061; cv=pass;
        d=google.com; s=arc-20160816;
        b=VWzGr8mR8ppkkfN+mu++uqVKWwAkBgsznSEO3mnoaNXdQQf3Dy3qDHPhUEq35gEGrj
         EvOHCuho7aZbr240SsiTKYJkPsVcdvRRjadGfQ9L9GNBcfGL7DX76eSU9DR9I5oVtqwI
         Pu/zN754ruldIHAlOQvYDWANa2uTxw0GVd+TEd6rtiK8W6v52OMx9osX2Ym+qlhBJ3i3
         KDv+10VZUknTXYjIqRB4Dxsvgna0WPU+kvRq7dD4gf8uHpIhnJgdN23UdIrFjW3CYZ8I
         p50VceeeCuPlfHWuGQq+YYLqGI/m01R3M8yrcUBTRHcqG+hAIg4t6/TKpeJa+Ta8Dx2Y
         qrrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0V/N04L3TfGpdzXobBYJSYoTc1LHPdmFucL3r1+3hyA=;
        fh=1uKcu4dZB1RzcgXpBpHdgfU8IBVX06uH+7ApT0cHPLk=;
        b=izmU2GA8jVMvQlkJp9eemhhugnSnvY+A2ckyQS5J08h3frGE6cGhWHwTgdyG0kPr5w
         RO3Xa3JmOxqW0u21SBz+TPXAk9udcscQfM65LSYaYurO99G0abx5XAUyKFu3JkwMCBc/
         mBVLfjXOFpPlPFO6wrKAIxHzrB2UP0qHXpvo+PFACi4VOIoQRKaI1+kuyri0R+EXBvyB
         EoATXW+mxzAKI0iE3pK5GgWuuvAk9Ott0eVKWIEA45KGT76CcU0HsVJ4E1iZfm+MiDCv
         t8qMu5AYUdAQvbt8gfjqkBQJH8iRstN4GNImAVey8CY4aK4oemnuYKUo5pyDYYtVY3HB
         riuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3sHJVJJ8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718958061; x=1719562861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0V/N04L3TfGpdzXobBYJSYoTc1LHPdmFucL3r1+3hyA=;
        b=mBPhzYErxSD9RHlF8mkVCEM+XngvxH7djkko8Kylcz97Y8bGPe77eWwVBc7OqpyoDG
         DbC2R7Y33V3SGESiNW5T8zeGNT6oHbpE8TYjrUFIdoHCWrN7tosVg/zMWil5+zak/EoX
         POee5GrytnY3SlmPoyJZsh1levOFPenbInvlNQEM/nY/YjgzZ+ndYCg48qCM0dZEWHPj
         sQyBi76s6bTAJuDRT8e3jd2X5iLxGUFkwCWI5YcGygD05gPbm9YfsYuSkscsogQVMRRK
         vmRXhMSxMyyM8nujS/lZKfdCWsh35/6koL+Je6dN+iqLtREN8jOH0Aq5tpWy5FQKJgSc
         YwnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718958061; x=1719562861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0V/N04L3TfGpdzXobBYJSYoTc1LHPdmFucL3r1+3hyA=;
        b=aBxZ3OLhIlu6uKUR2o0mEJXxy2vi/odiA97N7vkGJ1xGPuXs2JlpwwLX93ie95FjYW
         0qVE9CJznEAZgFd73cwha7u4TmVNU+V0KDfxH++haziJQTvr5dkASCTUXqUcqlz+8Ej1
         4WOFy8rOrjLJ4z9NfDGgaKV0hwxcVfS3/3NjErAwsjR+l3pV2hy0udDFkwD1iXT7G6VQ
         pr1RNBxUSbK0X3Uv+uBo0zrW6XGUYA9ay/+9S/PRUr4fTZ4A7PHf7MzWkTeyMUaO/XLi
         CfCQQGy9cKKxv2VUAZVSrPKCAJ7kefCFs8jzsejjwxjZkrtaJ5cXIimjtK37IqMvWGZh
         zOrg==
X-Forwarded-Encrypted: i=2; AJvYcCVMK1x9HFi+/dpjCTV1IbAT/uefYCUT/0QjD+a6ZCga7DtCUzfB8YOpubV0uUjrnPbUhxoIzNHd8H4sryjey4qNCeaofkwbMg==
X-Gm-Message-State: AOJu0Yybhrs2v3yujzH4Aw2m+gpFANaQdOHokWzz/OAPZ8MNaA8lqOu5
	6x4Gp/OM4U7wZwa0TRvaMEL/VvZhFuWSqbYaHZ0TpoMAfL4EADuC
X-Google-Smtp-Source: AGHT+IHuOICDDktPnW/Jiv+RuNPZi0L+cnyzIblxKMaUPRQHmTpLKTVF0ZsEQV4Pmw3RxMnnNuW1lA==
X-Received: by 2002:a4a:2446:0:b0:5ba:f9a0:e97 with SMTP id 006d021491bc7-5c1adbe524fmr8165274eaf.6.1718958061274;
        Fri, 21 Jun 2024 01:21:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3002:0:b0:5c1:bd4c:b16b with SMTP id 006d021491bc7-5c1bff28ba7ls1594430eaf.1.-pod-prod-04-us;
 Fri, 21 Jun 2024 01:21:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1oWu7NTbvMk7WhmUbVU5dEGnXbhAIvP2EDFFDiDh4pCqFRKCxUM9heoaN3HU8js/kLE0ZC3PqomAcTO3FtnVloJSYDZTH+C9Ntw==
X-Received: by 2002:a05:6808:2189:b0:3d2:4697:6b0a with SMTP id 5614622812f47-3d51ba740d3mr9044086b6e.31.1718958060376;
        Fri, 21 Jun 2024 01:21:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718958060; cv=none;
        d=google.com; s=arc-20160816;
        b=pAlhcdIQKUFrPx6Jmoak/wRy/EcNnIpEV+21mn2k2SKL2i8FhjXbU8iJsjCMeks7oC
         iZjjoAVOAggwXVvdhZt/7W8pdJmtBoytedeozQjWSKPpYjo8oKUSETvRCacpVvzul4lF
         gUbwj0V27rgzcCM0lmtQKxiZ6ydX92j5vAZLPeXAZi7R6kn7C+QE7fj/N1efjwoNBdgn
         i76jvElkmVCQjRQCEHXIky40Mn421vFSw7sLokBP853t8iotYTgTc/voQS0OFpFJksc8
         /BUsH4I6fak5Se1hN7bYsSiEz4Ifk0xhVe4Yl/T24T1rqfNhzK33xGDpXbDMnTT9r33K
         xIKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BHs522MQJBFhV9ohTCDDfuazR6Fijf/OOyDX4mfhwRo=;
        fh=Owk5Q8AlyZNvnubDihp+c9sgzeMhGEIUjMo0oAgIpYM=;
        b=Gn2SSDYoi6DFcPLM5m/gvbI232ItsQZ7Aaehw5oJFm7s8QJGYTy/0s8EL6AsalKEf8
         briWAwXKh+CHXt0+M3+5vbo0D9g9Etl3I2WWjdKEQOO3vqUdGVAs1DM1f623jkkxm/At
         mIN3Y++56DyAj1W223mXc2J+kt0nOmbQb+p9djTK0unfpy+wFxz5wvYNhnQDl7k5Xffb
         Ey8NhtZ7N0ArOonfC25tHrZV0WxZorhSZ2TBAvnHSL6Itgiq2REw/UWyn4LsnxN4h077
         OAIzgd5LduhsiqeYMYw4lbDopRtUBfTyRSX/7Y8BlEVU8Kc4M0I6+4OZHpsTJZV9raaY
         vSNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3sHJVJJ8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5346875e2si52184b6e.4.2024.06.21.01.21.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Jun 2024 01:21:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id af79cd13be357-79a3f1d007fso146792085a.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2024 01:21:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVIHIx28TXSYMhxAu7oZ9yBX7gWR4Jjx3ulMMwwPujzQC2RFy7QpUdJoa9jL7NaxhMasnyx4NZuDItzyS59L0n7cTozVBwT+ZRFaw==
X-Received: by 2002:ad4:4e52:0:b0:6b0:8f42:2435 with SMTP id
 6a1803df08f44-6b50d8e188dmr52575026d6.51.1718958059567; Fri, 21 Jun 2024
 01:20:59 -0700 (PDT)
MIME-Version: 1.0
References: <20240621002616.40684-1-iii@linux.ibm.com> <20240621002616.40684-33-iii@linux.ibm.com>
In-Reply-To: <20240621002616.40684-33-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Jun 2024 10:20:18 +0200
Message-ID: <CAG_fn=UNT0s1q82Jb=j+HAnGXJs2j=ip2FL6zut+jtnwq57pUA@mail.gmail.com>
Subject: Re: [PATCH v6 32/39] s390/ptdump: Add KMSAN page markers
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3sHJVJJ8;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jun 21, 2024 at 2:27=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Add KMSAN vmalloc metadata areas to kernel_page_tables.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUNT0s1q82Jb%3Dj%2BHAnGXJs2j%3Dip2FL6zut%2Bjtnwq57pUA%40m=
ail.gmail.com.
