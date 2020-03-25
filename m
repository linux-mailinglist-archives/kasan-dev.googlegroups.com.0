Return-Path: <kasan-dev+bncBAABBSND5XZQKGQENLJ26KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 332141928B0
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 13:42:51 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id 20sf2000322pfw.10
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 05:42:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585140169; cv=pass;
        d=google.com; s=arc-20160816;
        b=pwKoxmztNMuZxRSReqGglrEXB6dadK+jv5wgXW2HnjeBTZ79jQsFapUglEttmzq/ou
         2NVV1EUKJqjbKrAgHWyCLV4/ka1gxW3oEfi7SCgiPs32vO9zZASkAF8pmr2uNJJSG7fn
         ++2pcvVsCmSwl2FEV9KIzcObVBCaT2/DqmB42RqW4tcUomrcmZkeI2escHDu9mhuBhHv
         zyPU5eSCn3O6uWHU3MrFR1flGV6ueg8EinlhEhcWR/H0FV9vCJVEdLLQKUPis66S8aUS
         yycXv5k+ywDz0nv9iEZeqR1OuArL5HMWCyVL71fpPB9oK0NylusLFcooruVcGwlKAY8P
         TL3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6Eb2vWvdZn0qx2cIYNyGZI5GqnEh46b/7haRVwjTCGg=;
        b=hA9Qa20yL2ye34au0yczNCratnoxmxVBVSXLeP436lONxX/EUl4Es3V6Yv5R4XaDl2
         puUY6cMWmf3LvgxOfvyX+TpWBq5rAH7bzG3QVfzKmtBKcnMFz2AJhUBziyOsXgSSyR/x
         F1Ya2C5j6KwskbH9tXEEo3HyFDCAzK3E8Y4i1m1/y3B0ncVu/PUv7l2DBON9w8W34p8M
         Wh0LGduhcFvPpLJowh3na2a+MPcO5tktrIe+7ck1s6XgBgZ0ctRpJ7tICEEGBc8ilMHH
         LPCfbSCzimC0MCmLC7R/x+iyJWwhOgrC8rWSyXtc+GNqSbBvKHrC3Oif/GlDQFdBvroO
         HC9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=uk1q+G09;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6Eb2vWvdZn0qx2cIYNyGZI5GqnEh46b/7haRVwjTCGg=;
        b=J1yuItTtzGj0ggQVUOnhEWsBUtwz/z16t0LCVL4ys6MvoqIMgmJtX8mfvYoLEU2RIE
         5Mhn9TugrrLEa6JRzxNa5gr+ZTXkzMLE+bwr46FM/8FLyR5tLug+GrKv9lbGCLirIKgX
         higJdG7W5nNxOMVF2in4LQKJtmAfBNIOQ8WyLSKXAY9FfonRiZQlScNdDIE3aEzpk32R
         A+QxJr0tMHREW3uZYyt/C14pp6eBar4uFL+EaiSKZLYuey5C6TQ8ep+41iHPmBaOr0sw
         wYYX+5wM6u4cT8hx9kyu6ZFoyWdIiXZh40wrIPMNE/giYwL9CbXZKWR2mY9DEY74bmvm
         4bCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Eb2vWvdZn0qx2cIYNyGZI5GqnEh46b/7haRVwjTCGg=;
        b=CbCRjFvDdi9bBPuicBeCYT0fA75/US8njzgodWbkn+plJInnpZFRubbxB4mwmmrkkI
         ej/LDrHdTk2rM0wU2uC11qSojO3P4B5/z7MqcFnKwgSlxky7YGzZmnz9Hvj9zjck+rlz
         vTepa2OCb/On38fkjGm9al2/PJpYG4xTfDriZKjEfScQFqVAzqzKLpiR6heUuzHPXhl6
         bEt1txCBWbm2qQCa2jRkv20EX3OoRN0e7bYi961SiSwf2tP0vlWZSsMSjOjSudPDk9bI
         NWFGzuVUjTxS5nrpwOSXfXeDPB0Uy20Zq1ELTswolqgD/y6r2yGXBmPHCis5lpVfyyZd
         GjxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0BDSi01Kt6T0iOS8hZcmJFH7a1zrwCkGxldlFC7VJAszeb+a1r
	vJMyF/fIR1DQEM1vD6M3ODs=
X-Google-Smtp-Source: ADFU+vtdQHwTs32Y4XVR46nOXk46vKon8pr32lPo+/K5vnry5KcFjLcZQXp6b0UCBObZmkRDwOhNhg==
X-Received: by 2002:aa7:9e42:: with SMTP id z2mr3201739pfq.109.1585140169685;
        Wed, 25 Mar 2020 05:42:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9688:: with SMTP id n8ls1732563plp.3.gmail; Wed, 25
 Mar 2020 05:42:49 -0700 (PDT)
X-Received: by 2002:a17:90a:e397:: with SMTP id b23mr3678489pjz.137.1585140169326;
        Wed, 25 Mar 2020 05:42:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585140169; cv=none;
        d=google.com; s=arc-20160816;
        b=k5v846JQYV8lUG2MmVbceAcGhetuEQNJ5FAqyCxkDvp3Qh43m79nTKjqNFzyw+m0oe
         X7QeiIsuMy/tiRlQ2DqKPfTpd1GqNJBQgU6eM2mmWyqzETBbF86THUw785Prk6tQjwmk
         79agpSztyyUIAxfz1criC9ahMp8uVvEmnclEont2PWklAQjddB8XmfGWgUcPpLYLl9Xv
         JBy8ACeQvkxElEc6PMn5edx91zFesGoaVg09IwEREWEONTGzJoYZj++6KXvvTQMc4dzW
         uvu1iTac2aw1CBTAnZWEEo/idT0rl1cwViVedbD6Qxnd3J+J7fhV07fdcyNwx6q86Tvz
         4M9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=4CxQcsvrlZYbDGdz/Ttr6KfahZweiekg6E11FnAAvqQ=;
        b=WOXxMA28spnbcWdqZdZdUyxNyxGKtsGZ4pNbPASxjGWzLJgZNV1ricRGmOMO97UsuI
         YkGd++/DRQouhrauJjQ6+JPa8P8riWhFMUPdjdQ/+gonn15H/ZH4+KY0bSdF7xjOoNGe
         an9saKyOPq506XrtbMp3OGttvqZHDLNv0dwTzuw68B+1Lm1ahA6cSgffvciPdE0BDQMZ
         s6HoyncUqMsnzESf+r0BEQxz2WD+ml5LRj5pA0iJgGM1WMbCD7kx5MOC0nDp/FUMUIlW
         HX08W3fOt+9goGJEaWTg/DkOWZdYSmX3FIbocYuTXanL64+Tak83+Fo9Nxm4mSW5L7fr
         vQKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=uk1q+G09;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id c3si194804pje.1.2020.03.25.05.42.49
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Mar 2020 05:42:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 02PCdUAM052990;
	Wed, 25 Mar 2020 12:42:46 GMT
Received: from userp3020.oracle.com (userp3020.oracle.com [156.151.31.79])
	by aserp2120.oracle.com with ESMTP id 2ywavm9dj5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 25 Mar 2020 12:42:46 +0000
Received: from pps.filterd (userp3020.oracle.com [127.0.0.1])
	by userp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 02PCfbXI165088;
	Wed, 25 Mar 2020 12:42:45 GMT
Received: from userv0121.oracle.com (userv0121.oracle.com [156.151.31.72])
	by userp3020.oracle.com with ESMTP id 3003ghnayj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 25 Mar 2020 12:42:45 +0000
Received: from abhmp0012.oracle.com (abhmp0012.oracle.com [141.146.116.18])
	by userv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 02PCgh08017482;
	Wed, 25 Mar 2020 12:42:43 GMT
Received: from dhcp-10-175-163-133.vpn.oracle.com (/10.175.163.133)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Wed, 25 Mar 2020 05:42:43 -0700
Date: Wed, 25 Mar 2020 12:42:36 +0000 (GMT)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@localhost
To: Patricia Alfonso <trishalfonso@google.com>
cc: Alan Maguire <alan.maguire@oracle.com>, David Gow <davidgow@google.com>,
        Brendan Higgins <brendanhiggins@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Juri Lelli <juri.lelli@redhat.com>,
        Vincent Guittot <vincent.guittot@linaro.org>,
        LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com,
        "open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
In-Reply-To: <CAKFsvULUx3qi_kMGJx69ndzCgq=m2xf4XWrYRYBCViud0P7qqA@mail.gmail.com>
Message-ID: <alpine.LRH.2.21.2003251242200.9650@localhost>
References: <20200319164227.87419-1-trishalfonso@google.com> <20200319164227.87419-2-trishalfonso@google.com> <alpine.LRH.2.21.2003241635230.30637@localhost> <CAKFsvULUx3qi_kMGJx69ndzCgq=m2xf4XWrYRYBCViud0P7qqA@mail.gmail.com>
User-Agent: Alpine 2.21 (LRH 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9570 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 mlxlogscore=999 bulkscore=0
 phishscore=0 adultscore=0 spamscore=0 malwarescore=0 suspectscore=3
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2003020000
 definitions=main-2003250106
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9570 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 malwarescore=0
 priorityscore=1501 mlxscore=0 bulkscore=0 clxscore=1015 impostorscore=0
 phishscore=0 suspectscore=3 mlxlogscore=999 spamscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2003020000
 definitions=main-2003250105
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=uk1q+G09;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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


On Tue, 24 Mar 2020, Patricia Alfonso wrote:

> On Tue, Mar 24, 2020 at 9:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> >
> >
> > On Thu, 19 Mar 2020, Patricia Alfonso wrote:
> >
> > > In order to integrate debugging tools like KASAN into the KUnit
> > > framework, add KUnit struct to the current task to keep track of the
> > > current KUnit test.
> > >
> > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > ---
> > >  include/linux/sched.h | 4 ++++
> > >  1 file changed, 4 insertions(+)
> > >
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index 04278493bf15..1fbfa0634776 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -1180,6 +1180,10 @@ struct task_struct {
> > >       unsigned int                    kasan_depth;
> > >  #endif
> > >
> > > +#if IS_BUILTIN(CONFIG_KUNIT)
> >
> > This patch set looks great! You might have noticed I
> > refreshed the kunit resources stuff to incorporate
> > feedback from Brendan, but I don't think any API changes
> > were made that should have consequences for your code
> > (I'm building with your patches on top to make sure).
> > I'd suggest promoting from RFC to v3 on the next round
> > unless anyone objects.
> >
> > As Dmitry suggested, the above could likely be changed to be
> > "#ifdef CONFIG_KUNIT" as kunit can be built as a
> > module also. More on this in patch 2..
> >
> I suppose this could be changed so that this can be used in possible
> future scenarios, but for now, since built-in things can't rely on
> modules, the KASAN integration relies on KUnit being built-in.
>

I think we can get around that. I've tried tweaking the resources
patchset such that the functions you need in KASAN (which
is builtin) are declared as "static inline" in include/kunit/test.h;
doing this allows us to build kunit and test_kasan as a
module while supporting the builtin functionality required to
retrieve and use kunit resources within KASAN itself.  

The impact of this amounts to a few functions, but it would
require a rebase of your changes. I'll send out a  v3 of the
resources patches shortly; I just want to do some additional
testing on them. I can also send you the modified versions of
your patches that I used to test with.

With these changes I can run the tests on baremetal
x86_64 by modprobe'ing test_kasan. However I see a few failures:

[   87.577012]  # kasan_memchr: EXPECTATION FAILED at lib/test_kasan.c:509
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.577104]  not ok 30 - kasan_memchr
[   87.603823]  # kasan_memcmp: EXPECTATION FAILED at lib/test_kasan.c:523
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.603929]  not ok 31 - kasan_memcmp
[   87.630644]  # kasan_strings: EXPECTATION FAILED at 
lib/test_kasan.c:544
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.630910]  # kasan_strings: EXPECTATION FAILED at 
lib/test_kasan.c:546
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.654037]  # kasan_strings: EXPECTATION FAILED at 
lib/test_kasan.c:548
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.677179]  # kasan_strings: EXPECTATION FAILED at 
lib/test_kasan.c:550
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.700242]  # kasan_strings: EXPECTATION FAILED at 
lib/test_kasan.c:552
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.723336]  # kasan_strings: EXPECTATION FAILED at 
lib/test_kasan.c:554
        Expected kasan_data->report_expected == kasan_data->report_found, 
but
                kasan_data->report_expected == 1
                kasan_data->report_found == 0
[   87.746304]  not ok 32 - kasan_strings

The above three tests consistently fail while everything
else passes, and happen irrespective of whether kunit
is built as a module or built-in.  Let me know if you 
need any more info to debug (I built the kernel with
CONFIG_SLUB=y if that matters).

Thanks!

Alan


> > > +     struct kunit                    *kunit_test;
> > > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > > +
> > >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > >       /* Index of current stored address in ret_stack: */
> > >       int                             curr_ret_stack;
> > > --
> > > 2.25.1.696.g5e7596f4ac-goog
> > >
> > >
> 
> -- 
> Best,
> Patricia
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.21.2003251242200.9650%40localhost.
