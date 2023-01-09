Return-Path: <kasan-dev+bncBDW2JDUY5AORBSP66GOQMGQE76W3PZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 63C3C6631F3
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Jan 2023 21:55:38 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id l13-20020a056e0212ed00b00304c6338d79sf7008720iln.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jan 2023 12:55:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673297737; cv=pass;
        d=google.com; s=arc-20160816;
        b=1J15NLna5sihuGYevXYhCU2qNg8wa3IIORAWq1I9O7LZ/FgjBqstyn/Iv+8Rwiu5Jj
         nmCvGfeJrYhsN05WoMG/DwUU8pwksvBIxJ4XLWLt8KVSuXFQnY7gG/rgtixCxL3bpqgJ
         /gnydrSHVpjMlhKLByvkz4NhwPXlnjYOTcl2R+t0+sSmXa2HFHeapX9KpZnD5i1oZMWK
         maJuKLCRk/8APMlTZmCd5WAdS2XvJT3NCDPBa7HuUf9K0Lw6jEH7KSl6pyp49RE612B1
         DnqsUOMBIWsDxLRf96YeNXhcUIIZCzAuqy43QcgCzXxWQlQoUAuzs0sqk+Q5cUKCN11O
         gNrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=mNXAlZ4jinoo2nCrqpdGJH/YkXXg002/0E6oJoYM28s=;
        b=nosLDJ3LdkoAJKPgNPyqrATUC8ISdNWDhLbNGs32vERY8zWe8tCAVd/NOGrqXVjOWE
         4t0xvfzbrzn5wf6nDV4UoMm3wDlqnFKE386SBVuGENFH2DN3sUv51BsiRhig2E7YNUwk
         UzG3/Go/lq9XOLtNtqo1LHlT7kYIqPkLHvt/xr5Dq1ud6A4ldXdCxI0yBn+UvAeiaWtk
         rV6MV7mT9YC0+6SkoRoSMqVIpsgYU8ccc04kQXPGLKn73cQ2lnNOoGEa02EjCiEDhSTA
         Hzdipz+9IXgX6Z6euGZL1JJsvlhdi/92SUg7ES5Boi/9ICBXOJ0UDI13hdgwFDvbiG00
         PRXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XXSphh6W;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mNXAlZ4jinoo2nCrqpdGJH/YkXXg002/0E6oJoYM28s=;
        b=YR1u6QYO3c/Jp241l81UV0nD3O8iPouvTnERVGz2bjvOHMPkHQ3/HT7ByJICJ6hB15
         X3Pr5LTyHY+roEpXYNmzveiDgTf6Mi0zvTnPwoDjZaIci9aLTGidlstJ5ElLY/DNRTOr
         k1MSs1DWtFTAqBYhhp5S3j4gVlfP3ryf8ypCVelaNdepIPYveMphh3PQS31HaWUukOlN
         aOCGODGCiFWvpg00ywqrV5jxQZTXO5EkN4fXRyIXC4izYn+asXdNPSIu2AUaYGrYs0W0
         30/EJ4sZN5FgE8JhQvkuFVWjsXirOlIzy/vB7YTGTi9U/jQe858vP9RnJNT7uLODBX3B
         i1pQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mNXAlZ4jinoo2nCrqpdGJH/YkXXg002/0E6oJoYM28s=;
        b=XFsGWYyEPufg8GlwtCdWNsGTengpHfrr0GUdF9W5iMdrtnPCa1/LqHqxgSUx9A5Tpr
         N1gP07Mln4WxYPmnY2GyupDTOFgTPOOGyROKFdzKDzzeoCpLOz8wopAGSIt5c7Zh0KyS
         o1WpJ86orAXLYV8hvueIZyWdQrDq829vsobZ6GyjGlPFvDrwFr7M9ye1DHTZlygleMCm
         oqmQcJ8xn2Vlv3lhG+uZBSK9nHAnhjWCEG8EYD/N8Cvo+/Z3i5e183qjBJ0VFz/uIo3X
         oALDFRvo9GliZK3XJ/5ypb2WdrPsFFk8/BRfuqWGaLK3EPfzvT2+688GOjSbth03oOWz
         Ckeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=mNXAlZ4jinoo2nCrqpdGJH/YkXXg002/0E6oJoYM28s=;
        b=TWrSEPVVGcIIE4392h6JyBYW0W6zIvvoWsSfF+UuhVR6NTPmn58ZQt/It3KSCKzfIT
         E9NlX/BI84csL7XnZyXN0mVPsQ9lUyFIA7Gr35orpiit2bZh0PlUd8NKqvYbpo8UK9aR
         zk7uNyVo+WbhiKHsBuubf7v8yJMX5U+34RFWNZqJHxF6INpQtquv3NEuzR+DCgz3lTp8
         KsQMDZ/8K5f3sAhZ6GNhMrrzg9fyQjW9KfqgKa0fXiWiGOMhjZQ8FOrhEnWFtgWw1Nhk
         llH+jOv88u0K0rj4m6CTPrBOczm3S8E1xZKRxaXTTiLTbre7Ba6oyo5NroEvdsvxs9i2
         F9GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kphnU2h9EGpuaq7vIFYAUtFyHPB06RsxJeW5t/0SdIcTDRNK4tA
	jd+1WaImMagv8knx9G7uIsk=
X-Google-Smtp-Source: AMrXdXsT+e5jTYEWqE0vV+oiftTpVjh5LFE/FJYDQMC//Ckt1oZlJuycAyNQgnq050mwgAFEyIWVPQ==
X-Received: by 2002:a05:6e02:be5:b0:30d:7fd4:a6dd with SMTP id d5-20020a056e020be500b0030d7fd4a6ddmr2909176ilu.20.1673297737114;
        Mon, 09 Jan 2023 12:55:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:8ed7:0:b0:6bc:c593:b6b3 with SMTP id q206-20020a6b8ed7000000b006bcc593b6b3ls1291523iod.6.-pod-prod-gmail;
 Mon, 09 Jan 2023 12:55:36 -0800 (PST)
X-Received: by 2002:a5d:8b45:0:b0:6e6:3314:7b0c with SMTP id c5-20020a5d8b45000000b006e633147b0cmr53370844iot.1.1673297736684;
        Mon, 09 Jan 2023 12:55:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673297736; cv=none;
        d=google.com; s=arc-20160816;
        b=brGvyPoxQXescXVTudyVv0aN3p7nrpLS5KSyUQBYtQfc0SNqXkP7/EnAsYkzSKk2GU
         VCZDd0TGKXlNCXN3qHFuGktSZAokpdJow+TxbgI3d5UkkU+GM1kyMAZcdj8CZ9m3N1L7
         tLybT1C2xFQ4TlG5RvDD0V2BhDQDZ0ocFcoWV7TJfuDoyyo0uvDZGJ4/K+VfoQhqKUJZ
         eo+uDtwyFeaBF1L/XQl24cGmHHaRj80D4r1YETGPJCwY1+UP47TWlfa+pdCigyON2MLg
         NHvClHSDBySK3w1d8DzNwnEguHgitYV9enUj5/GdkcJ968oMI3p7OddC6FnfT4ZjzpDh
         WucQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EI+HK5d2VVHprte9/R4H7nRhtttrT0pgRQ4cGp2gqIE=;
        b=MGgeFYf7XZ4UMZIRknZdtNomGoJ0t1Dg0GJfKu/Mk2dtEZFuV6iXzdnzYxcETibbFm
         xzTVmBQXuExQnmsODThEHcZwBTjxg4yKZbtwjntcKWmkfP1j9k97wNU57Yg7BaHGqdp3
         mPZfO1UXw0bH/Fzs1cL7sLwi6l+aksL+rcqrnj9HxIk6KNwZ+YB4xO7kFkwqBwIkrybL
         DkZmZ78QZ6h/OpyiPNsV4Ki94B6PqN8ganOICeTpqo92lddT1e6L0PdG9NJDG0FDnDW8
         qqgpBFZye4xFyoPLt5jwqisDlJukO1BPiREtax4MSNIPKgSOGu7B+zEwQmEWKFauuRlk
         l41w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XXSphh6W;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 3-20020a05660220c300b007045222d9f2si83386ioz.0.2023.01.09.12.55.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Jan 2023 12:55:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 36so6743923pgp.10
        for <kasan-dev@googlegroups.com>; Mon, 09 Jan 2023 12:55:36 -0800 (PST)
X-Received: by 2002:a65:6bc5:0:b0:478:31a5:3656 with SMTP id
 e5-20020a656bc5000000b0047831a53656mr3286091pgw.273.1673297736001; Mon, 09
 Jan 2023 12:55:36 -0800 (PST)
MIME-Version: 1.0
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
 <CA+fCnZdk0HoWx6XCbTsiNhyR2Z_7zv5JUdgNs8Q_tV4GRkkmCg@mail.gmail.com> <dbaeb044c547ddb908bffdce4d2dfa0936805ef7.camel@mediatek.com>
In-Reply-To: <dbaeb044c547ddb908bffdce4d2dfa0936805ef7.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Jan 2023 21:55:25 +0100
Message-ID: <CA+fCnZfhH+XRU-Ywvb6WThjmwuSODfNV5fNxDpHY1enibdNYSQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: infer the requested size by scanning shadow memory
To: =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, 
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "glider@google.com" <glider@google.com>, 
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=XXSphh6W;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jan 9, 2023 at 6:02 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> > Let's leave the first two lines as is, and instead change the second
> > two lines to:
> >
> > The buggy address is located 0 bytes to the right of
> >  requested 184-byte region [ffff888017576600, ffff8880175766c0)
>
> Did you mean region [ffff888017576600, ffff8880175766b8)?

Yes! Forgot to change the range. The idea is to refer to the requested
size in these two lines of the report.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfhH%2BXRU-Ywvb6WThjmwuSODfNV5fNxDpHY1enibdNYSQ%40mail.gm=
ail.com.
