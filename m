Return-Path: <kasan-dev+bncBCII7JXRXUGBBJFUW2OAMGQESBZUS5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 93DEC642375
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Dec 2022 08:13:41 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id r203-20020a1c44d4000000b003d153a83d27sf2280608wma.0
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Dec 2022 23:13:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670224421; cv=pass;
        d=google.com; s=arc-20160816;
        b=QUKu/pj6Sl/lb0uf0yAUcjbA+P8+kVyOFNQfbuJX8/I57jd3/j1zWnXXokEVcyWx46
         TPhmjCTzjun38AV5VUZbIDRzHHloXnuzJKuWkIIjSEKXk9mFS4zuzOYNQA/kWsX+ZJ+N
         6i35Plvu9lpZZkQJHP0J1ymWap0DVW6sBrB/6bIwBq6jIE8DgAFTJZpzHa+twMgefsjm
         zqoTZn4sXYiyr3X0zAhftL5wDnWt/pF/dAfDTzZw84OX/k9Ni0B3Fk7VVsscKRgD7m6c
         n50FvACkl+J6+nI+lOqxdOByZ+mmwZC6ea/KY/7ZQrsljLRNrh8KjC7NcxIvdn+DSUk1
         vPBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MyxdEJpy/uBuiAx4abdK6TgZguf8EYAKrfuG3O+nltM=;
        b=UPzhMcj/xoyEsd/OeAGyMt4qk2yBExtetlGC03wTp4apTeEbL4kvkxFdWdf/Urr4jo
         cyEVHq5Ze7UJ/dpY746aCvVz0RpMyqN/M88P6MZnlQj8VlTZsa98p4U6+vTj32PfJVlO
         3LwXQemGvdRByXF+U4/25hy2zqHGyoCRuSJR8EkyaIM8yGTMrrBSjSlWs8VMcupRM81L
         1PmWtH5UD3IKdCJC5Z2DzPfkqxzz0TEURNbe707zSspt1IAnheULbxedUSbq0os4Gn/3
         y3+E2nwVjc3ChuOYh8WMxJMvho+5X+eTuYT/X88ggHyWvmkP+SG24G65YlIlaNjZxJdJ
         CycA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=KxQeiB3T;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=KxQeiB3T;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MyxdEJpy/uBuiAx4abdK6TgZguf8EYAKrfuG3O+nltM=;
        b=XzBVbieKloE5io6SF1PEb77Z+/L60teQIRLpzaczkrEuIbuTmTrEJclN1xaS+7n5ed
         OBUCg8HfcRi2zS6BsOvLbt/CqxRiOcKuIz537Cjkj4KKJXl4KZUzIv9ijzGFl/lhH/Y8
         w7MRoeSht3PomVjMXKo4PQ8vC2EJ8hCNSwHNtTBjSDV6rmyAwCWSQ78QLJsFd+brofkz
         LKI+y1TWWdhOTuBxZ1Oge0qNczck5UHXfcVa0xndlUuyEHKMX246s7duRAhrwNaHWK6Y
         cCsI84B2SXfjcspSVTyhhn8Kex+c9r9gbZrx8xP5+E8ilw6/1BxT00ObfpW3hXZ64VLt
         lN/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MyxdEJpy/uBuiAx4abdK6TgZguf8EYAKrfuG3O+nltM=;
        b=nH667LxddZtoZC/n8eZ2//mslmcARQL643P7NQ5+cqcJV7EBDlq8QS6y/qzvGd699w
         YUCNgu96ltsry9uNCg8kB9o8cMqLwD26D416RVpQPzPuPX9zn9BhVh2+vIPvt5g/O9of
         HWFU6+aDHFMVrLqdZRvRSNUbOVeAhbj1/2aSUvXBvPP1z/ah5Jp43DbFj6QktgmxQLEw
         /ghNI3gdXJxP7pSTdGj6gDZ0dPp0dY26S+zlVGwc4VPH25c9wyNs2jOaDQ3JEi4A6H0s
         QTiONm7WkKK/eCJavn4xrHRb5dnLEU9RUq8/uiSgS3zZAjdkxxoqHgaxjyoYZMk2nMNS
         ng/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmGwrycTSQ6bRaBCpa3VbZbLEfQQNt8oRvDJ+2zfLIzbBvrlhpg
	+LcJnCUbQ3x6iQ/ErwVj1sw=
X-Google-Smtp-Source: AA0mqf5JkJqv6OGAqdCe+3F4xTV9WQ9WJiK+PRxMENMgYdNEppcyS6tVoZIhHL8f+TjqlnNr2QpWeQ==
X-Received: by 2002:a05:6000:a03:b0:242:67cf:a572 with SMTP id co3-20020a0560000a0300b0024267cfa572mr952526wrb.124.1670224421080;
        Sun, 04 Dec 2022 23:13:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6447:0:b0:236:8fa4:71d1 with SMTP id d7-20020a5d6447000000b002368fa471d1ls6935335wrw.1.-pod-prod-gmail;
 Sun, 04 Dec 2022 23:13:40 -0800 (PST)
X-Received: by 2002:a5d:5266:0:b0:242:5878:2927 with SMTP id l6-20020a5d5266000000b0024258782927mr3840921wrc.488.1670224420001;
        Sun, 04 Dec 2022 23:13:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670224419; cv=none;
        d=google.com; s=arc-20160816;
        b=IphxHCW1betsJNONHmzQERNp5nzZGZIxbsYRPMhfXxy2MbOM99JGkMIuCK9b3dQRuC
         SKfCLTG4JE5PuemtzsfJVeNN/qEzktw1DAVaixUoK47tEF1hnshFbP8bSfh+MQ+fPpEK
         w98frMguMXu2blJxRLigseQOFEsjx1LNJt3OUZfLvOZQ442znWGJhtzwAJ6bP7h9urNd
         nNBmUjlFlilYBqvJ+Tw1hvkn0+hZqEIgjfnaw4tYnrsa/Qyv5MTKLebHrI+vVxRytpxI
         P6c0GLj8fvmi3md+ynxIifCClTg0fgExNkm6+SEgAL3ywGpnGWxiKSCFRdUJghBu7MTF
         D99g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=2/E7M28jlzB+tOHKj9EI5rF1sUTSmV05NM5sZZy2Ges=;
        b=dJ6qmL6C/uzM6MwT6m9XaTGPBiOWj0VIqd0p2XyuyoyYLv7U+bBsGyG11wD6QsAp5j
         /sM4kHvqLjwmXT+UOM3mzYgQjO5BasJf00ankIy7RGzWyHLJPcCUCIzqt5Dpf8TGwNGI
         Re5TP+AI8VvBdu6wIGsPU4ymm2IlH9fAjF0EjbB0TIzBwGtyUWLJj3WK15MsY7STmfDw
         D1ZRHF7kOjOyKYx0+2feLNdMWTXA2cBvA22+HUwJ5A0fBu+hYaxiUtvpD0czoEymaOI5
         VH/BCdQuAzQT+tlMLiVmHZpSpAlCZiO3f/0iBPZYbhbzZT7CEQzdjdqzjTfGJL3umQVJ
         M4jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=KxQeiB3T;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=KxQeiB3T;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from nautica.notk.org (nautica.notk.org. [91.121.71.147])
        by gmr-mx.google.com with ESMTPS id n7-20020a1c2707000000b003cfde9030c7si656905wmn.0.2022.12.04.23.13.39
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 04 Dec 2022 23:13:39 -0800 (PST)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) client-ip=91.121.71.147;
Received: by nautica.notk.org (Postfix, from userid 108)
	id EAF43C01B; Mon,  5 Dec 2022 08:13:48 +0100 (CET)
X-Spam-Checker-Version: SpamAssassin 3.3.2 (2011-06-06) on nautica.notk.org
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=5.0 tests=UNPARSEABLE_RELAY
	autolearn=unavailable version=3.3.2
Received: from odin.codewreck.org (localhost [127.0.0.1])
	by nautica.notk.org (Postfix) with ESMTPS id 60CC5C009;
	Mon,  5 Dec 2022 08:13:45 +0100 (CET)
Received: from localhost (odin.codewreck.org [local])
	by odin.codewreck.org (OpenSMTPD) with ESMTPA id d99753f1;
	Mon, 5 Dec 2022 07:13:32 +0000 (UTC)
Date: Mon, 5 Dec 2022 16:13:17 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: Marco Elver <elver@google.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, rcu <rcu@vger.kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Netdev <netdev@vger.kernel.org>,
	Anders Roxell <anders.roxell@linaro.org>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb /
 p9_client_rpc
Message-ID: <Y42aDQ0ZOUt4dvYc@codewreck.org>
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
 <Y4e3WC4UYtszfFBe@codewreck.org>
 <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
 <Y4ttC/qESg7Np9mR@codewreck.org>
 <CANpmjNNcY0LQYDuMS2pG2R3EJ+ed1t7BeWbLK2MNxnzPcD=wZw@mail.gmail.com>
 <Y4vW4CncDucES8m+@codewreck.org>
 <CANpmjNPXhEB6GeMT70UT1e-8zTHf3gY21E3wx-27VjChQ0x2gA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPXhEB6GeMT70UT1e-8zTHf3gY21E3wx-27VjChQ0x2gA@mail.gmail.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=KxQeiB3T;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=KxQeiB3T;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as
 permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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

Marco Elver wrote on Mon, Dec 05, 2022 at 08:00:00AM +0100:
> > Should I just update the wrapped condition, as below?
> >
> > -       err = wait_event_killable(req->wq, req->status >= REQ_STATUS_RCVD);
> > +       err = wait_event_killable(req->wq,
> > +                                 READ_ONCE(req->status) >= REQ_STATUS_RCVD);
> 
> Yes, this looks good!
> 
> > The writes all are straightforward, there's all the error paths to
> > convert to WRITE_ONCE too but that's not difficult (leaving only the
> > init without such a marker); I'll send a patch when you've confirmed the
> > read looks good.
> > (the other reads are a bit less obvious as some are protected by a lock
> > in trans_fd, which should cover all cases of possible concurrent updates
> > there as far as I can see, but this mixed model is definitely hard to
> > reason with... Well, that's how it was written and I won't ever have time
> > to rewrite any of this. Enough ranting.)
> 
> If the lock-protected accesses indeed are non-racy, they should be
> left unmarked. If some assumption here turns out to be wrong, KCSAN
> would (hopefully) tell us one way or another.

Great, that makes sense.

I've left the commit at home, will submit it tonight -- you and Naresh
will be in Cc from suggested/reported-by tags.

-- 
Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y42aDQ0ZOUt4dvYc%40codewreck.org.
