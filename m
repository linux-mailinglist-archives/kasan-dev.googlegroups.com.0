Return-Path: <kasan-dev+bncBCAJFDXE4QGBBHPSTW2QMGQEFAMCKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id BE3A593F3B4
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 13:12:30 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4280291f739sf16773545e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 04:12:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722251550; cv=pass;
        d=google.com; s=arc-20160816;
        b=0X2jJU5eqYenA7VY7CfxtMi9CIw9KaEhk+YenhCf/bfvqLqhQCSkNkg+cDa0sxzgha
         7btKUf3t9+ucy/I80B3v/iIE+ULCFJONrOi3gnIFdxO/j5oteWBamnwETiQeFWOSDcmW
         f8jmEDD6AUc9+v3m1eSXFXcfFIlUeFmcRplYxaeVOqYLa0Rj7o0xms8hOIFJLdzzGV7D
         6ZtKzWaF8snEhhLPVxXGueNRU3kCKUFef1TAhulZ0MsiAnJCaaJ7OWZC2BJ01+PKudGM
         XOVsLB5fgqAQWF4Z1VhQ/SQWTftd8ZSIKE55ChUnn/nUq/ZrAIho/PwnZqip72TtK1Vt
         LuKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uEQpc35cISV0OOdkg+e6GUfMHzecxn4H6ht5rWs1/1w=;
        fh=eQ+Ah/tGEF2KsZpKhHS8TvJuh0UdnIYaymiXOSu8P8o=;
        b=MiY/FmPcat/upzF2TTgijLYlZEZuEwIsxSEKeUr8m7ycTGyO60DIna4s6C1cC1tt5L
         2LiFBtYGSEaHUVEydDFLoYw5n8o6zgGwTa1Y1PuBca7Ba3J81iExYbNm8SeMMmXfJVl8
         ZdWDKJO76lffNQ5HG0xyxPu4K8Hr3vfi6FAckVpkDWeuM7x+K1ZhfgyF/gwcz0GkFIZP
         u6f8pNBLSzCO6lRi/NqKjO0YcY741yrpOMawkop3N+i4buTczXLZxY2+ACJIzGUGlFZK
         OGMCkROsYIIkX3P4PdMcIn4YolEzl9octX16iIu6Sc+vkMzVq92hZWOYGlPI2kRrpJLa
         OEeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DUMRMqqA;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722251550; x=1722856350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uEQpc35cISV0OOdkg+e6GUfMHzecxn4H6ht5rWs1/1w=;
        b=CZx+gX+Zos/X41jw3xNMzLPAKkgDfMXW+b+V54HJTPd5T/BjOO8oCRFA1AV6lgfsvy
         JzQdqDUIPMAm3ronmbHDfbrQ4kRUbTk3ij1nHRDFY0SJ3KKrfsUPSY/MYCWr4vTkOHsp
         Tg3a0g+rN/oPAMOT/bZtyAZ1VCFLkWE0sbiB4wgs+AWW6eL8mkbp/abjtc/ZDPhBbqAG
         1Fst7u9/zgZUl6ifCq0vmoUgsmUI7I3su5EIrQtGadptMlRDMqm0E5WSl+m6NUbKjzJg
         yjORrjCG/brmGNlYnHzgJqr7Awz+SYtXRLNY+Tbw2MD8NVtpCju+JRm1l50ZarHVMLPK
         uImw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722251550; x=1722856350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uEQpc35cISV0OOdkg+e6GUfMHzecxn4H6ht5rWs1/1w=;
        b=XnyD6rRJZ9GO/fvIhuLVKETNhWaIDC7UfOueUY27qyEp8bMgGqtQK/5HRxxbK0tMc/
         Ui8oQjgAwsh+X93SMARtTjtcrnVEuKb3K7rMpN+dX+hY71keAGKkCtoWLA1qJsGbM8mo
         KCJ3DNJ1VMg8b96GsPT2P4q03GDDLAWMKbkcypHykSysxe344mS8w0skXRCGg5o9wdsy
         VdnqdNk4gnZIU/VXJXD+VO1uP7lPdBUJ6hhv7QmAbgNV9chuJjGU5UPEnRJQvcIIWyTa
         d2fin3lazE22j3JxCrxB6py1wlyKagJ2XYHTRNoJjMxBHBkeQbQ+kmd0moVRdU3zvRc1
         xt4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722251550; x=1722856350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uEQpc35cISV0OOdkg+e6GUfMHzecxn4H6ht5rWs1/1w=;
        b=l5TUQqalUKFaioxi8HOyLe+muQ5mvbyVPBhzGpQHSTHf9G/kZAkM21ES2L6VlEns3L
         aUWeBB1N/Ve6j6hdeCDEeSkMifvc9EIKrrAi76SUsxnR06GLz3gqc+h/iO5O1GbCUfc2
         n92NyRTwMmNf9Ez6W/VgxUogXABa8FyS/+gPLh/okHLn4W2oaVMyMCFT50LSrkyPujy7
         oJ58slCRR4TXt37qoMUDl+NXGRYhYCjfBCTkP0nCzLJH653WzFQjtuTm5wMpvky4uqs1
         BKhmzAmlCaCvPOl9Bw20VHGjCoRqmG3V5ZoRCC8sx/QrE2Ip9bW5FIfJpQ0fd+3sDOjB
         0iBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVphbrMnZETYkepkHUvxlYQbKs/b0Av4OyYPTMwpzEIGNx3Fnawl7VGeZdoGkCS5ySzZAG4T/zuB9T+k0gq8YWM2o++BVFbQw==
X-Gm-Message-State: AOJu0YwAYNOYNp3EC3BEO9f6pBKijzypJ8H3oI9xkFTdF4Dlr6rW475/
	ZazJuy3Q2iFPrnExuB71FkNpivf+f/ctaFNvXNgsn+MaFGesARJ9
X-Google-Smtp-Source: AGHT+IEBmyxut6fuW5dyzigu3okoZPidd7K5yzXxfJRWug0qDcOxc3vvnp8TEoFay9yxuaa+xCn4rA==
X-Received: by 2002:a05:600c:3112:b0:426:61e8:fb35 with SMTP id 5b1f17b1804b1-42811d82e26mr48305275e9.4.1722251549545;
        Mon, 29 Jul 2024 04:12:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9a:b0:427:96b1:a664 with SMTP id
 5b1f17b1804b1-428038870dcls19526925e9.0.-pod-prod-03-eu; Mon, 29 Jul 2024
 04:12:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMGX1GimzxOLttITkfvQf1fAFVATUgHWTM9rY+7m0Jb0OeXOR7pK2FL0EGPvueC3iJYyNOnrfy3WZPxuUP0pdzf/Tq9MEMZW/JVA==
X-Received: by 2002:a05:600c:1f8f:b0:428:31c:5a52 with SMTP id 5b1f17b1804b1-42811dd7a6dmr44692135e9.29.1722251547695;
        Mon, 29 Jul 2024 04:12:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722251547; cv=none;
        d=google.com; s=arc-20160816;
        b=noZK58yKsJfIxSVyaCnn6xVxaHhC1UQpBVAUSBKQ4eDFzRGfWvplocXJZ1fO9KRo/9
         ltkDeVZzLJlAT147AO/Qu70hrKEWQrHaevIDy01Dn6kE9Qj+frCfTXzJr+Y8MKavcnwU
         XiApusZCAAu6/Pp87wSkSNOqQqEwx75WpR4cIOxu9l9znTzwCMQa1Zy8z9aFeCVK5BEr
         cTPxCsv+Yfa5kNqsw1TJigWRj0PpNUTu1NRBNyc0PFxP761sRC1xcJBSnkU5wdysYrn2
         guvFCq4Pz1UTrBo49x49O7NKk5XXUEkIe4+aNlYw+oeCS7Ksx0+UTYEeUA/4xwVSXv2p
         4LnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rdY4mJRd0oeIvInVYbrZM2hv5BYVyhNVq+NkJ96ZB1o=;
        fh=JtmESGuMH4/3NUZzMrH7Tz4+ECvpyWvWS3itqtab2LE=;
        b=YQ+06+RmxS74fmFSsUh0EK07eTAlZ4zKreORnHyGmcZXtj4oNOTxgT30ng8EB8mhoE
         FtcQgA9z8jbM2UYjy7yPy9ZdFr/4mUd4UDI9q3ZWFlnlYlUJ0NwdzLyD4p5p+iZsVi+N
         Nel2hlcJ7bEAPcB/gC7oQ56fU89QV26vyG7z+SqfAszBX3xEm8rHxPIoWxgLLEfyIPUT
         Gh09UV6j694G/4kci84V+dliwbojxJnUdrjBzC4BM6LkjyOV1xBa19Di46M7DOr/bgtw
         xeL5SNJmrFkI/fckoGKC7lk/7QHaNTRZUFnyZ/eSPjI/0TwFQE3eOqpGWRkWKRarzTYN
         zvhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DUMRMqqA;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ef3f44b4si10116925e9.0.2024.07.29.04.12.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 04:12:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-5a15692b6f6so5541288a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 04:12:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQ4FIivlfAvWM637xtABGY3/Sp7JYvI4wEqjlkYEHigc6ufWqLo5TZpUT2WxyUWPyn+YW3BIDG1HwrOWBbG13J0wQSSP7XsjvZ1w==
X-Received: by 2002:a05:6402:35d6:b0:5a2:3453:aaf2 with SMTP id
 4fb4d7f45d1cf-5b0205d6d60mr5778076a12.10.1722251546666; Mon, 29 Jul 2024
 04:12:26 -0700 (PDT)
MIME-Version: 1.0
References: <20240726165246.31326-1-ahuang12@lenovo.com> <20240728141851.aece5581f6e13fb6d6280bc4@linux-foundation.org>
In-Reply-To: <20240728141851.aece5581f6e13fb6d6280bc4@linux-foundation.org>
From: Huang Adrian <adrianhuang0701@gmail.com>
Date: Mon, 29 Jul 2024 19:12:15 +0800
Message-ID: <CAHKZfL3PjWSEFRa3f6kBqx4YSsCWumK8zi0V1UEX_x+oDZZ1pQ@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of KASAN
 shadow virtual address into one operation
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Uladzislau Rezki <urezki@gmail.com>, 
	Christoph Hellwig <hch@infradead.org>, Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Adrian Huang <ahuang12@lenovo.com>, Jiwei Sun <sunjw10@lenovo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DUMRMqqA;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Jul 29, 2024 at 5:18=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Sat, 27 Jul 2024 00:52:46 +0800 Adrian Huang <adrianhuang0701@gmail.co=
m> wrote:
>
> > From: Adrian Huang <ahuang12@lenovo.com>
> >
> > When compiling kernel source 'make -j $(nproc)' with the up-and-running
> > KASAN-enabled kernel on a 256-core machine, the following soft lockup
> > is shown:
> >
> > ...
> >
> >         # CPU  DURATION                  FUNCTION CALLS
> >         # |     |   |                     |   |   |   |
> >           76) $ 50412985 us |    } /* __purge_vmap_area_lazy */
> >
> > ...
> >
> >      # CPU  DURATION                  FUNCTION CALLS
> >      # |     |   |                     |   |   |   |
> >        23) $ 1074942 us  |    } /* __purge_vmap_area_lazy */
> >        23) $ 1074950 us  |  } /* drain_vmap_area_work */
> >
> >   The worst execution time of drain_vmap_area_work() is about 1 second.
>
> Cool, thanks.
>
> But that's still pretty dreadful and I bet there are other workloads
> which will trigger the lockup detector in this path?

Yes, this path can be reproduced by other workloads. The stress-ng
command `stress-ng --exec $(nproc) --timeout 5m` can also trigger the
lockup detector in this path. (Confirmed on v6.11-rc1)

-- Adrian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHKZfL3PjWSEFRa3f6kBqx4YSsCWumK8zi0V1UEX_x%2BoDZZ1pQ%40mail.gmai=
l.com.
