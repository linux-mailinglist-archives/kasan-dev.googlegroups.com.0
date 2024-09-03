Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBRXM3K3AMGQETT4SQ2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CC089694C5
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 09:10:00 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5df9ac3042dsf5222785eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 00:10:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725347399; cv=pass;
        d=google.com; s=arc-20240605;
        b=cVef1ZNZHx4V8nRH4WCjqw5+bmmgi38m50qOKuc0oLQ/bVBOCEZpKCDWV0qte8WzKL
         e2a6kfcjCFjbl0+1uDfGEi/dFTuPqjjct5f7nb+zlekNJsiyKOzze00VsXBA/V2ZZBoH
         sRhTw3MSLI7406uqHp17Pxb+vPmOcZHf4vRusG3XBXlhS+GmQbf+hjDVuUcYU72CtdPZ
         IZfas8mRpd/mXUw4yXnK9yNa2xLP0hINhSy4j4VCqh/2pk/J1TZsgBe/fYGe3anbzn1A
         /r0sR7Zr5tjoJ6VFmArlM/dVYLeMqpn9exy9r0SSus4J0+gxzAoUs1MWw9rZsuUkdL70
         jP8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=bsz34leR4NP9m8ExcNyLypSS+RE7/veQj1joKCuiFUc=;
        fh=G1ZYNlRsGfsOQ+IQfQKMsPVH+Jqg9Aea3g0WnqF5lsI=;
        b=SWbWcZynAz0OdWIfNlAcIK2CzHD5yvBkTqNNSgKeG7WKfz567SV/xTm+kW7ERu1dYw
         ApA6MMwbTSsfidJQAwQxWNsSFU8rRww3pePKsvDCWRcyj9iUYmPIFqAxAnya4bOVrGKx
         8cjKm48govXiVEpiqZnpK2B1gF0pYBsfs8usahqF0t8EACGDYK12XMIryh+NFbwYFxFk
         Rww+QzyIv93crHY2VLVkFmDasy54PS0CarmLQBHmcxJXJqf4mZXJlkMu+uHR16v5Vm82
         Kr0Od0wo93dZ//VNByB7BgknTZn5J8IO7BWyzDp608PVU6X7NwMsI34U+FXrqtKeLO8m
         nmJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=STnHriJm;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725347399; x=1725952199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bsz34leR4NP9m8ExcNyLypSS+RE7/veQj1joKCuiFUc=;
        b=B8XolJ14cqlNAD9787asfHkdwtMbrv1pmJtVKXc8XdeBC3Oijr5pBlOS/m2qZ/pkZV
         TComO6F6i4clFL5MRAAauCimThTiUWfwPxbJzjXB2pE5r9Qcok6uko/5FyxscCcKpVuj
         0rIKg4Q5mLTLP717TdE5mYEgJYUQtlr3c+/BDvQm4giQ59qifdE3BD0ZIlZG4e80YzUE
         CGXI8ULTVr7Pcm9ZYtkIATuUgT1V4WWFFFqNrXVPDC2R+TX2/W5hDQpyraFWjY6UXNQu
         ZrHiQZ9/YwDvj+/OZYjp6IUgtb/BDCh5jJbnYB7v4YAe8YlObClqq4/tzaF7XXrvf8JX
         ItoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725347399; x=1725952199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bsz34leR4NP9m8ExcNyLypSS+RE7/veQj1joKCuiFUc=;
        b=KZqqELIyOd3GQC69Y9Gu6joKKLfLKTKrfDKi7TaQMKaQQ4h8a32s+370yT0JdfX+nm
         fWEXyMAPPL04wJ9NSc17tJgme8HX1MwJNVnWim53RpT7JDJYtqqYFSsUhHhRezV7CMZK
         q5JAYCwQJEwVjRQZ7P9fruH3J5eqxd4SI4A2brH7a71WNQW589hgUGi4gyBijMwJ+sdm
         ncPyNzmZ4s030GsALMOoih6OHyxVKIE6fpjzVe7RP/HyR22njT+RLfFA800bDifldUrr
         gDi0elfpRqxD52YAsejYj3VzpgU0UhRC/uzZJ7/rnMWAJidgLazw8LwUHhjKZ/o90h15
         tj+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN4NhwoR/GmOUlX4aT1gbyAKz5BQ9PnP62cVtgrXMAxjIZgRp6eOqQ0wDDE1NIS4BTTwOmvw==@lfdr.de
X-Gm-Message-State: AOJu0YwhjynmOMieunDdkfRFDrxzGmghhRn/SJ052RBgkw4qio6JJLC9
	WdbH3Q+2M2fanJyEDIHHaiNzwukUK/LOrlQKwvQM1M2qlgeJm2+r
X-Google-Smtp-Source: AGHT+IG2Uimm2J8eJSFHJ0BwNz5dKl3YK1f4NgknM2ZhHjyf3a9c1Fo/yNeU9AziXKUGGuUuvrW8Aw==
X-Received: by 2002:a05:6358:60c6:b0:1b5:fb36:8176 with SMTP id e5c5f4694b2df-1b7f19e1294mr1347675055d.12.1725347398887;
        Tue, 03 Sep 2024 00:09:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:852:b0:714:2ca8:49d4 with SMTP id
 d2e1a72fcca58-715df4eedd4ls3303087b3a.2.-pod-prod-07-us; Tue, 03 Sep 2024
 00:09:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXo50GK4CsXVWnVCTbKC5kUDSC5AtWHbPF2NevbPVSBA4wRCesS/J0lr/SmGU+/RtpoRb/0FwuZYKE=@googlegroups.com
X-Received: by 2002:a05:6300:41:b0:1cc:be05:ffe2 with SMTP id adf61e73a8af0-1ced0468f79mr8484346637.18.1725347397579;
        Tue, 03 Sep 2024 00:09:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725347397; cv=none;
        d=google.com; s=arc-20240605;
        b=M/QpB2jdpbmnVqXATaH0K7UGWiuEBowIW3Za6GjwpVnx3nVKpg4zameLVynZZwCEv1
         tydZF6EKs/BolyenGAFWgSENIxqU5gJreGve6aDroAlnnpjWb2IU1p/eCUSRyGam9woY
         pOzzrapUH+UTnEwLxZQHTkEZyoOyju9KWvd1xZCf9MXZj6FjSfSkdfdxpveD/1U/2Se6
         5Tr+P5hy+sgpdZITYNjsUHNO9Y8Pe1F1L5awNE+I1dtX3jwS6kEPqzojFrJetn6fYhX0
         x2Ko1LgEaCJIrS1ANbdBvS3qA0H9wHe3hng2cbdwrTE//QVFXgZ8ztc1LVom8GsVoBp7
         aRYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=mBrYBheCx9wkNXDMw7EicMa3H2OzuhbqLk8GF6LfcGE=;
        fh=OOjTkQIgiCOv8Ea6SOC+tL8SVzsLULLTG8TN39ZK1I4=;
        b=MJOCpKprDEtwF2NqtrmpJIyGGx+bNd77uWraEXaZ8l6KNOnlx0/6/gX1rN+3N4AC2W
         Mry3Dg4msoyGLcZkBrXvqYcZ9NyGFGNiPmam0QJkN2uX4Me1jliBg2cl2LT6CehqK04H
         rPuCFuatPoPs6McxxLSq9nDrHBu0h7Bv82CBXtBUSMRgGiCfRQtRcwLCB53dMutcFRW5
         UCV0WyPH1YKPXtPWv/4wJ7DKIeKK9aakv8Jb/JVbbCiH9yJ2IgBhLE6y1CVTQE6rXrui
         uSTuYEdSc+wZasVkE+22vX92+myKpvJV6SYWv9XmzxuHfWADbDdREHsriKUeUx3DZ2v8
         8tLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=STnHriJm;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d82a68c6besi1048481a91.1.2024.09.03.00.09.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2024 00:09:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 6D4C55C57FA;
	Tue,  3 Sep 2024 07:09:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F0A8DC4CEC6;
	Tue,  3 Sep 2024 07:09:55 +0000 (UTC)
Date: Tue, 3 Sep 2024 09:09:53 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alan Stern <stern@rowland.harvard.edu>,
	Marcello Sylvester Bauer <sylv@sylv.io>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org,
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com,
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com,
	stable@vger.kernel.org, andrey.konovalov@linux.dev
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
Message-ID: <2024090332-whomever-careless-5b7d@gregkh>
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
 <CA+fCnZc7qVTmH2neiCn3T44+C-CCyxfCKNc0FP3F9Cu0oKtBRQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZc7qVTmH2neiCn3T44+C-CCyxfCKNc0FP3F9Cu0oKtBRQ@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=STnHriJm;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Aug 27, 2024 at 02:02:00AM +0200, Andrey Konovalov wrote:
> On Mon, Jul 29, 2024 at 4:23=E2=80=AFAM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > Commit a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfe=
r
> > scheduler") switched dummy_hcd to use hrtimer and made the timer's
> > callback be executed in the hardirq context.
> >
> > With that change, __usb_hcd_giveback_urb now gets executed in the hardi=
rq
> > context, which causes problems for KCOV and KMSAN.
> >
> > One problem is that KCOV now is unable to collect coverage from
> > the USB code that gets executed from the dummy_hcd's timer callback,
> > as KCOV cannot collect coverage in the hardirq context.
> >
> > Another problem is that the dummy_hcd hrtimer might get triggered in th=
e
> > middle of a softirq with KCOV remote coverage collection enabled, and t=
hat
> > causes a WARNING in KCOV, as reported by syzbot. (I sent a separate pat=
ch
> > to shut down this WARNING, but that doesn't fix the other two issues.)
> >
> > Finally, KMSAN appears to ignore tracking memory copying operations
> > that happen in the hardirq context, which causes false positive
> > kernel-infoleaks, as reported by syzbot.
> >
> > Change the hrtimer in dummy_hcd to execute the callback in the softirq
> > context.
> >
> > Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=3D2388cdaeb6b10f0c13ac
> > Reported-by: syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=3D17ca2339e34a1d863aad
> > Fixes: a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfe=
r scheduler")
> > Cc: stable@vger.kernel.org
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>=20
> Hi Greg,
>=20
> Could you pick up either this or Marcello's patch
> (https://lkml.org/lkml/2024/6/26/969)? In case they got lost.

Both are lost now, (and please use lore.kernel.org, not lkml.org), can
you resend the one that you wish to see accepted?

thanks,

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2024090332-whomever-careless-5b7d%40gregkh.
