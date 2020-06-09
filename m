Return-Path: <kasan-dev+bncBCVJB37EUYFBBIGB7X3AKGQEAGXTSHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 608841F37B1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 12:12:49 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id d18sf2025488pjr.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 03:12:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591697568; cv=pass;
        d=google.com; s=arc-20160816;
        b=h+o2tDqkutZijgMPg3gb5kGRHzhT/qgwHSLCoct3QWwpEppJgGmIOVLmjheT06p4sD
         xsbFzBDYwH2PeZ17wNkGKRFTyfnZzH+es/XnJZC+/sJUeXP0ud4VXNAGZt3n+fPqcpz0
         nfGMHhxoE1wjpj3Gn+Zslbl8YrJuIrYUkgp3qms9b2cdOmJWFNOEQCeIJtHDI5DZfDCH
         KwKiV9dywqcNw9uA9do1ImqDKiKPg4lr+VJFW2xJXigZeqotzq/lmTIj47+TasL3u33t
         dL+l5gsOeSeOIqe0pRek28lXcZ+g/L2Rczumn/7OT4LDIwh6H+zVImkmFOjTNAsYr97A
         QMnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=x9Sz2DbiQqOpyih6V/QUrmti3qaMts90TMIHDQVO96k=;
        b=f5Aqd1lp1siEdMZZJMYRv7XB4M+xjUXvDriL2Fb9fuJpQGzSQJl/cgyvnVR4Ks8CTr
         xyqIMni0aTgk3cmjpC2Z07W2lnlppEglvbtsL9HwQYLM+Ra3anuO9UT23tKpWCiLGi9W
         Gf11qn9aIppO8KROQOCiKN5Wsd8b8CiqjEC1PU94IEadLCwGQx9fRHV2hQAswBpUtApT
         0KHhINE+KXkNhj7cuS07Ct6rHfIcP/GzaybN2uEhSsA/4afiGYHzWSdtp2rNvAX9v8Rz
         2uQDJvwEhgPEKpfWublFsq4QwhosUYXQuadFu4sjZxx8oGChkDdjqIeQ8mZRVXj9KKm/
         MuJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ISpfGb3F;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a9Xusl7n;
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x9Sz2DbiQqOpyih6V/QUrmti3qaMts90TMIHDQVO96k=;
        b=ponxVNLZvxCElDx0zMxkh2ttQkIPFUhMcWCGpF6FDRPAP8jiKZ8wvOTIm/KG7+cnTM
         mWZI2ces9VZfeqNPSitd1YaYtroYkcht7W4AT23Cqj2FFdyLbzra7Df1L+ix2Qdo/2F6
         7JVKNZiAqTLEa1/DzqIi35az5W+YOpBrrzluHzPG49f8XTtkxsq3YibWAts/dX6oeJiJ
         PoXahM05VbJDvKYqJ+YtlJ9txEBLWkVA3lt40wV9c0MowhdAe9viQqfSZ4XoskxX32ig
         DMD54bYVmGlZISOaV82OlKll9QQFfxsxk3L06L057S4KJCjlIEf0pgyL5dZmr4YxZFem
         LYLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x9Sz2DbiQqOpyih6V/QUrmti3qaMts90TMIHDQVO96k=;
        b=WIoF+eo2V/W7Hs2LoWBq19K08wTLnvISZbyuMLPShW70hV/aUVlFaxM4u9pdDTNpFD
         B4pRl2x1/RNQsZ3IAkT+tiiDN6nzJxWBrj+d3WT3f6cFG03+8Tvu74ZQDsaYuVc5xMrj
         0lN+px3RmjQwPH++02VpwSg0779D73uK55p5nQDMNhPwMuCbqG5UC8JDwT+hnBuMm/Do
         lxX47PnFeqNeXujzUhENk9Eeswv5fRO5CNfnN3qVy9wQ+vYrJcESenOAtyiKtCbK9Z7N
         RAOLxmsXSzHVzDPVXcngVcogzVHdvIrdWhJ1JMBglXrvIDKnNL+F6woUKej9x9Ugi0uD
         Mj4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HZsZp4geg2viYjVARWCioMuL+aOckSOirgxTHsXgCLSA+wnSo
	C4LPTuWlbfbOh40M86kS2io=
X-Google-Smtp-Source: ABdhPJzp4eeb3VwHp8nWbQgIJbxLGIvKUom/Wrho4oiy6fxegxLQ2N4urMU87AnFKkINOxflcSnJqA==
X-Received: by 2002:a17:902:c3ca:: with SMTP id j10mr2657127plj.7.1591697568105;
        Tue, 09 Jun 2020 03:12:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls1271879pjx.2.gmail; Tue, 09
 Jun 2020 03:12:47 -0700 (PDT)
X-Received: by 2002:a17:90a:294f:: with SMTP id x15mr3782350pjf.97.1591697567713;
        Tue, 09 Jun 2020 03:12:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591697567; cv=none;
        d=google.com; s=arc-20160816;
        b=o90K6KRZSaDPx2wmXjOefdjv2KfmtvNAS15GcSRCRjftanfIh3paABtriBkWQOJzgt
         vXg0QuJfHYOECjs+9alSa1DTwURXpl6L3PNIQApZrfGiK47WrxwA7sYpTouxCW9t5LXJ
         f8Jk/I8HLTK9+lSe0zwLuKfic52XXUSuTo/p5lQigzE2REyhPr8DZX0fluBKgbDT3oT+
         v1nThJAzfm4V+X+nzFMRztqT+fxuIJtYwwZ9kKXR3giLVb9vWHdR7oBB/ZL5x3K5tBlQ
         1HHExWFVxk9zmV3KBC5hpp2FYjp0DeEBZdGn18aS1c47Av1hG+glcYbYFR4M1l42nZ8h
         /1Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:user-agent:in-reply-to:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=3U9J6+w5G77/x3LYu9LhQ1b50CS7naEXiTfVgG76lRg=;
        b=a/ROTbKbCT4U9Q7G+hI5KvQk1Q8acYI+8A/Ca7hNfGOVKLIRZUfDlePQDFDg7perL9
         Y0rrPnQHYGt8NE0gPkOZG7r5nH780xGiUftbRKpX3jBQfMXe5CbhkGFd0h94m7kWY1kc
         jrHeI/vH4tYJez4ecCvPppyXaISf4XaemYpQIU7QcrBAPTHTprxU9cGKOlMCWpWZehX3
         eXdu6b4IxrjF4oANfEyYmiSQxy7SqaDnC8J4qlhQnf1xzMeHaGcankCp7TYQtqaqDDxQ
         Pq4qiwKPo1FfaC7ZSKrlaRQUb0sDPyFxPZGxwHOR7BxzlaJAr1QlfdCywcC3E436Max3
         /hJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ISpfGb3F;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a9Xusl7n;
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id e6si565430pgr.1.2020.06.09.03.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 03:12:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-492-5uAiJj-_MZuRQ8gpDGDmFg-1; Tue, 09 Jun 2020 06:10:35 -0400
X-MC-Unique: 5uAiJj-_MZuRQ8gpDGDmFg-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 461851005512;
	Tue,  9 Jun 2020 10:10:34 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-94.ams2.redhat.com [10.36.112.94])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id BB27A100164C;
	Tue,  9 Jun 2020 10:10:33 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 059AAUiJ008284;
	Tue, 9 Jun 2020 12:10:30 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 059AAT7C008283;
	Tue, 9 Jun 2020 12:10:29 +0200
Date: Tue, 9 Jun 2020 12:10:29 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>,
        Martin =?utf-8?B?TGnFoWth?= <mliska@suse.cz>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Dmitry Vyukov <dvyukov@google.com>, Borislav Petkov <bp@alien8.de>,
        Dmitry Vyukov <dvuykov@google.com>
Subject: Re: [PATCH v2] tsan: Add optional support for distinguishing
 volatiles
Message-ID: <20200609101029.GZ8462@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200609074834.215975-1-elver@google.com>
 <20200609095031.GY8462@tucnak>
 <CANpmjNN8bokP95tkHV_HnmFo8w3OksMHw4DDFJLh_5gU4g0m0Q@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNN8bokP95tkHV_HnmFo8w3OksMHw4DDFJLh_5gU4g0m0Q@mail.gmail.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ISpfGb3F;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719
 header.b=a9Xusl7n;       spf=pass (google.com: domain of jakub@redhat.com
 designates 205.139.110.61 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Tue, Jun 09, 2020 at 12:08:07PM +0200, Marco Elver wrote:
> Just wanted to change this one, and noticed this
> 
> > > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
> > > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> 
> is precisely 80 characters. So if I read the style guide right, it's
> <= 80 chars (and not < 80 chars), right?

Ah, you're right, sorry.

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200609101029.GZ8462%40tucnak.
