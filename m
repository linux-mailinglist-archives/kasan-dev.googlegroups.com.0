Return-Path: <kasan-dev+bncBCKPFB7SXUERBWPA67VAKGQEODI4UTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A4A2C988FE
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 03:31:07 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id t10sf2286686otb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 18:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566437466; cv=pass;
        d=google.com; s=arc-20160816;
        b=FlB0EZ7OuOwG7ZAKQXqVGHi8j7d8p9C1dsnMvsXRzbHLM+UTty1xV3VodKCbWl9HFe
         XwD0YJ/SOEd5mVgKxQjrxCUjj3nDo3kf/49opIo0ZgBn470YLwKK1EsBzWwT1cem1PLE
         GBUXzF9ktbrxOd2+FHcEYHNulI+BB4vKRf+fXQBqWzC3wzx39DTwyZRiRhEPhzLdhtvL
         2dbkRxTlRTwQyYUUqQOtqogHQdy1yAR9LnkQWxrheff0Spkb0D8x4gW/1FeoTFB05TZT
         WQC0WsSqy6A0XEemDJ7CqMw6bBL/lrjXXJpPQJ2Cva3wXDA1TVHYMoJWWx32i2uPF36k
         0OcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=m2yuay9b2aG8WYGPXgbneWwqdzJsO9QsIEWyy1d1rlc=;
        b=Y5U0VfMmIdhH1/bSseCMKMkLfY6fPCAPSYNMi7htlXBY4EPJx9Th0Dm0TsAei3lABI
         shMvbNv7/ZU7YikPMNNFpHIzubh39mr21XHVSZAREi+7v1IMfhhJq1cn4TekxF7MOt4f
         qPZhFKTMUhx42qaUx0ew082uDd6zplhH+C/JTN6ZHHfpgaUvv5KxxSI0Scv04B6PELt6
         yguBdj4DLXBwHpbh/n8nCQuPGsZao8QprLG/UcZCVQuDJj0638z0NR71odTdtNCIAOIQ
         jPeKYb0QyIwoQqtFdCJ98S2tkpgrutrddwrMzEG/7FKhdm+SF+XOYichgIoouePaCxri
         F0/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bhe@redhat.com designates 209.132.183.28 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m2yuay9b2aG8WYGPXgbneWwqdzJsO9QsIEWyy1d1rlc=;
        b=BC4pwvZ1OUzvdQcoVWiWCRey8MWjKp3oJxK6He3O0HoXTzjFfnh5DZQNWxXV3eqiwT
         Qf2REmG4URtSaqlZ+SUvW+0q5HDXzAvkrbmVj7cp24S6Cwj2IZXQFOP/2lZZMB8E1W42
         EfVzbpKBDCy2CJzmjNOg8sLY5BbLk8CHZDYHQiK37K5CSxjQZ/uy/yY6g4SXZJ9XzGEp
         uhrR4bN1RU2hXxct+F4OdTFUeVufARyZueCbBS6iQU6s5M/oLzO04ayZ+p6y4pwFZzw4
         If2uC1A7KLCsfs0gTR8V6bXFL8iTCj40MhBC6A7ioq22DLGHyGqWM5V2NbmEh4pwV927
         oY6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m2yuay9b2aG8WYGPXgbneWwqdzJsO9QsIEWyy1d1rlc=;
        b=QpR+6pV2TB/5K5AJS1mKXc6QgdbbD5klkGiV0hS/YqGnIyRn9LrIa/qOs1Ph9cKnLp
         uBTSW4a7E833F+IbZpNqmkcImB8hsXS0cGKcRk0EFgWem8hFSn8tBE0Y0eZ/wbW4Ui8H
         jhsatvu3XnwzA7DDLHhUCOka5siqs2EYKS1jbHcCcQYixV2gW60bKxuHiFoYyXuVgawa
         Zdw/VUvJCNJCEHq/wM/UDfty9MfeZR5mhnRdzWGu/QqYuWqQyoo2z0g4uGC06Dfliibo
         7MjSg8pt+0Vu9DJja5c8QefaSPlGfGUBUz8mU/kGFfKzzPlRr2mn/EclheV4AIAh64iq
         HXMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU+KdW7l6BlerSluMcHZ+DYzWjI3Df6wV/ec/qpekLcsWwGqpVS
	Lz+Rm4A6OpTMc0tk50zb75A=
X-Google-Smtp-Source: APXvYqyxMnKklB/tNYJ9mpARw4VlFzoK6WhvVqSyWgx2F7yNCP6NwIKBKY0uaOaoWvMdJ2lcO6cLSg==
X-Received: by 2002:aca:c453:: with SMTP id u80mr2152386oif.8.1566437465950;
        Wed, 21 Aug 2019 18:31:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6250:: with SMTP id i16ls163834otk.1.gmail; Wed, 21 Aug
 2019 18:31:05 -0700 (PDT)
X-Received: by 2002:a9d:3ec5:: with SMTP id b63mr29768912otc.370.1566437465699;
        Wed, 21 Aug 2019 18:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566437465; cv=none;
        d=google.com; s=arc-20160816;
        b=Nr3gPuEq+7chQt/8XLjEFQffoQ7TEdTt/zYk5zrbSltAiG8EunjXNziruAFnfbnRkK
         zMpLk74JZtu0a+czW7FNBFif+/JIPpLEW5EIq/dTogwG2DSfqdnMeAjqjrMC5Y183gwE
         FBFkqo4AJEhTvLSdl25QoPm+3N8332PPunfXo0/zuZD/IY68vup7gpq8SN6XVD1ZU89h
         tkk+T9QWuk0FoSiHyp+Xz00ZPm3Oz5XClBiaPcj/vSVsXGqiuan9xs7VN9cRvj+i4Be4
         ZpvWy6xKBF7Wu91Kb3G2CTMOXiCYscgXpugvD5P2UxhHeTtI44Am+f74EgyffuddnGEr
         bH1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=2iOVB5ylO4L512CPvd9IeHaND+hYMGCln38/B1MSmNs=;
        b=IEp7aoIDa21YONh4OqD7yZuijW7mj3XhWHvk0ebBxm2cJfMoI2JRJErnHUKeJH1uo2
         eRpHwzyAg3dw68s4E/uu3rCr3SDDgXK0M2rsDHo1MZAkOvsWpVrJLAQzqeHXY0ADwfMe
         BBXogDNXjTVDL9IHZt/vGPy+vhysUrLPm180zz+EdwwvU5vxuESDU98hNmP+i2B0T4dD
         5pRcRdyKfxEge4i1GISlav4xNZdLlddsxwsqyvaU/rV0oDoUiDHWmRf6bjJarXlu9XWQ
         1SWiVTvocWEzfUlfDrr6R/vmTZFfieTjZOrHHut7HK3oSGDrjedftPWjr2ZvIrKBW40c
         AGww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bhe@redhat.com designates 209.132.183.28 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from mx1.redhat.com (mx1.redhat.com. [209.132.183.28])
        by gmr-mx.google.com with ESMTPS id u18si998204oie.4.2019.08.21.18.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Aug 2019 18:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 209.132.183.28 as permitted sender) client-ip=209.132.183.28;
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.phx2.redhat.com [10.5.11.23])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mx1.redhat.com (Postfix) with ESMTPS id A3BE710F23EC;
	Thu, 22 Aug 2019 01:31:04 +0000 (UTC)
Received: from localhost (ovpn-12-48.pek2.redhat.com [10.72.12.48])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id C02EA3DB3;
	Thu, 22 Aug 2019 01:31:03 +0000 (UTC)
Date: Thu, 22 Aug 2019 09:31:00 +0800
From: Baoquan He <bhe@redhat.com>
To: Qian Cai <cai@lca.pw>
Cc: Dan Williams <dan.j.williams@intel.com>, Linux MM <linux-mm@kvack.org>,
	linux-nvdimm <linux-nvdimm@lists.01.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com, Dave Jiang <dave.jiang@intel.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
Message-ID: <20190822013100.GC2588@MiWiFi-R3L-srv>
References: <1565991345.8572.28.camel@lca.pw>
 <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
 <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
 <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
 <CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w+GoxgmiW7gOdS2nXQ@mail.gmail.com>
 <0AC959D7-5BCB-4A81-BBDC-990E9826EB45@lca.pw>
 <1566421927.5576.3.camel@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1566421927.5576.3.camel@lca.pw>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.23
X-Greylist: Sender IP whitelisted, not delayed by milter-greylist-4.6.2 (mx1.redhat.com [10.5.110.66]); Thu, 22 Aug 2019 01:31:04 +0000 (UTC)
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bhe@redhat.com designates 209.132.183.28 as permitted
 sender) smtp.mailfrom=bhe@redhat.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=redhat.com
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

On 08/21/19 at 05:12pm, Qian Cai wrote:
> > > Does disabling CONFIG_RANDOMIZE_BASE help? Maybe that workaround has
> > > regressed. Effectively we need to find what is causing the kernel to
> > > sometimes be placed in the middle of a custom reserved memmap=3D rang=
e.
> >=20
> > Yes, disabling KASLR works good so far. Assuming the workaround, i.e.,
> > f28442497b5c
> > (=E2=80=9Cx86/boot: Fix KASLR and memmap=3D collision=E2=80=9D) is corr=
ect.
> >=20
> > The only other commit that might regress it from my research so far is,
> >=20
> > d52e7d5a952c ("x86/KASLR: Parse all 'memmap=3D' boot option entries=E2=
=80=9D)
> >=20
>=20
> It turns out that the origin commit f28442497b5c (=E2=80=9Cx86/boot: Fix =
KASLR and
> memmap=3D collision=E2=80=9D) has a bug that is unable to handle "memmap=
=3D" in
> CONFIG_CMDLINE instead of a parameter in bootloader because when it (as w=
ell as
> the commit d52e7d5a952c) calls get_cmd_line_ptr() in order to run
> mem_avoid_memmap(), "boot_params" has no knowledge of CONFIG_CMDLINE. Onl=
y later
> in setup_arch(), the kernel will deal with parameters over there.

Yes, we didn't consider CONFIG_CMDLINE during boot compressing stage. It
should be a generic issue since other parameters from CONFIG_CMDLINE could
be ignored too, not only KASLR handling. Would you like to cast a patch
to fix it? Or I can fix it later, maybe next week.

Thanks
Baoquan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20190822013100.GC2588%40MiWiFi-R3L-srv.
