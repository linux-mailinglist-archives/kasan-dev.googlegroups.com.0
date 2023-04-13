Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB4D4CQQMGQEUQO7IKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 306DC6E0E6B
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 15:20:09 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id n9-20020a056e02148900b003263d81730asf26321608ilk.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 06:20:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681392007; cv=pass;
        d=google.com; s=arc-20160816;
        b=mujyF22xeklPXeogkgVqHTiwIe5BLbvJa9/QYI3YlYU5djqs6tcC7EPboblJNQQoiW
         k7Xt+88UORJxNrV1rXkQbUy050OdLe9byyavC4NY39d/0PA/XmjpRW7RxoO1EUoqAO+m
         2IBIlIEOxvLzKIYg8I+SdF9tgeVBQqd3LrlcTbAlZ5wa1nVI1624wsvllfkzL6w9/jPA
         ErzbCJTRkblltZScpiubn/sKe1zARCW0p3m6xI/tN1ZSWNxdHGrbqldzLywX7sI9ax8Q
         RCgWSSEyAkqIhnULhih5BQsSTHizeSPsTHY5/gazegh5Cd4hvNpZ3ynw1v3fGSGogYzS
         +BGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7hfH3QWJRu/tMq2x63wMUDT0uOQDNm5/mnPH7YPdW4o=;
        b=Oh5ogXHgGa6NG+1d1gQpUt8mCBC5V1GIM3C/7VSPK7IaAN9iCRNtUVbps0B6XnQ22/
         T1ZfDxnIKb0x2DTjhRaRoADWLrroq7vzDz6ZpfYP/pWiM5PkMe/cuCaRDtuX36XNbdZR
         rpwN9s7D4oZPd2OJazwT4nZI0q25t2FyEm1MprdnCyMEJuKeApDPcoNx8WOmzx3HgEzq
         ThCA8ZROTsyzhv755F7BHmRJKyuAMKWIM71YW+j1RUI5p8F5NlHdDYG2/7WeRMd7IZkn
         AAXIUt8vAVmsySCTlFrHotgZYx7ZEfU4HidzWFhiTAntxZr9icLe3tApTdQIdLBl3cUu
         2JgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=tQ6wJTzC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681392007; x=1683984007;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7hfH3QWJRu/tMq2x63wMUDT0uOQDNm5/mnPH7YPdW4o=;
        b=Ufu+Z//btoQ5iuoJ9s2cag0MTYg3xZ+PetJdPIaATS7cyKpoMUrA96bKn68CZkoLY9
         ktW2tEx9eVamHLCGLc8DVcPrhsERRhIPaSvTtVQFDwlyOq5I8RmAwHoUjZZnOXrK9foO
         vF0Ps0TCMFKXzGycKdR6usv9dnVlxfJFOJYgfq8gl9VNolkn/VuQpuuiqGfFGYPLYyap
         pY49ogoTAZfijP98liOaJJbUgvRdadedoe5Rz0QIu9hj8SifRaja48D7J1pIZ3xgVpJx
         u+6NAk/YH1i82ftZX4NfoGIpGFznTFnGQqBhoxGvZ1hCORTlAwPARpIqqX7BrRHVN2wb
         IiNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681392007; x=1683984007;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7hfH3QWJRu/tMq2x63wMUDT0uOQDNm5/mnPH7YPdW4o=;
        b=VYauspu0yf4Sycw8UTPEa3+ReMoAyNNMlsTorZqwWLxIExxn8/9GatLU24wEJ5GLXa
         YP7nqRrg37w811Sm0YoH+cmN1fFQUwhQAUSTw9ph8wYwkHJTVyNZO/fbbR+VUW5Oa/1R
         +v419v/7NdithjTNVVmtBrP1Lfw+kA+e6Ixj48HSyPNrQ8VZyUlJtWSwHKbRf9ILvYlf
         H4IAnwVU0lXjOKbyNfHuuozjsUEwxaQlCcedOfjFqH0gMgrB7/VN2SdOW4TXhZ0yck/D
         6MacDkvJ2QcZ4p7FY8d1gz71egrVl5XxLk6BdPJja9aW2orED7DL067NPMfya4qkKab8
         BLWA==
X-Gm-Message-State: AAQBX9f6QaH3e9DeEMaHgkEGrpkySrrUss2/x0LT4ApRpMIak/2B/2nx
	E6lFWcpbKb0L36wpa4HjD24a0g==
X-Google-Smtp-Source: AKy350axb5Y3q7xNXy9WV8+96kieQ8vifoAlucvIOL69GPzoUBwFzhkwS57UVuRa3NrX/53fsc9rKQ==
X-Received: by 2002:a02:b0ce:0:b0:40b:110a:32be with SMTP id w14-20020a02b0ce000000b0040b110a32bemr660424jah.4.1681392007487;
        Thu, 13 Apr 2023 06:20:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:874d:0:b0:326:4b:d61a with SMTP id d13-20020a92874d000000b00326004bd61als12693066ilm.1.-pod-prod-gmail;
 Thu, 13 Apr 2023 06:20:06 -0700 (PDT)
X-Received: by 2002:a05:6e02:786:b0:325:c8ed:6775 with SMTP id q6-20020a056e02078600b00325c8ed6775mr1121571ils.18.1681392006867;
        Thu, 13 Apr 2023 06:20:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681392006; cv=none;
        d=google.com; s=arc-20160816;
        b=DkXi1CMPPrQ2NXHdxrf0o+mSFfXH1cUeidYxt5KHB94rI1phjavRWRx3c2R9t77fZJ
         P4w9YcH9Ef9M4r6RJnE7emL6HDQmyhrQtT15So8/+K3RI6oYcxqCr1H2NA4fzuu0srCw
         bn7vAy1tXuD8GrM1V/ZEYbn4RkHgTauK2SHvHiccos67kcXKktCGNvHbA1s4oiX1GBs8
         1fVtENiHQwovQtVsP2FG45r4nwImRbHOKymjfeXvDN4mlF5HCtmrzBs0+41HXBn2scD2
         6LOlSb8s5AVzTJ0qUCoQUrbs+ki50PHFe26+s5KucVDyJuH12k+22Swkf3Co8wHrvw4V
         BTpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OEYIJxcj5kmzNVXSipi1HyC65eTywMQLwhS5DFReugM=;
        b=aRohsj7i8ySsSh3z17Eo21J+eFITjpYT+bcIQh+SZkLBUs/JwlYe6Lz87aC2xVS3mL
         kR5vitG0MyRMctZtHlV//jYQg8nQ3Hij9wWys0M6H29RmWzNHV7Xu/kQJw6gn8cnlaR6
         X7pZfglMfdOhwnelLg3ovGMwCBvhCiqKx+pxVJ2od6jctsETN/92m7NSPeckPqhKWLZS
         QhC25FjAvCShOSiyh03VCl6/EKDhxpuvPvfDdDYzWrZ2+B31LXO5LxSor+5iVjWU11Bl
         +lX0jgewDjxbnobPfwpdXH81KsEMZT/YDnEGJmC7tI7PKHoPoKhymwt9RgT+h1zoaSTA
         Wd5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=tQ6wJTzC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id p16-20020a927410000000b00329639fc241si80886ilc.3.2023.04.13.06.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 06:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id c7so546473ybn.3
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 06:20:06 -0700 (PDT)
X-Received: by 2002:a25:d003:0:b0:b8f:32c4:c6f8 with SMTP id
 h3-20020a25d003000000b00b8f32c4c6f8mr1775428ybg.42.1681392006415; Thu, 13 Apr
 2023 06:20:06 -0700 (PDT)
MIME-Version: 1.0
References: <20230412145300.3651840-1-glider@google.com> <202304130223.epEIvA1E-lkp@intel.com>
 <20230412140601.9308b871e38acb842c119478@linux-foundation.org>
In-Reply-To: <20230412140601.9308b871e38acb842c119478@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Apr 2023 15:19:29 +0200
Message-ID: <CAG_fn=Wqf0E0Uo8wA5pdhgpreKZB7TPU-DiyERyG=T7bqqiJ9A@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm: kmsan: handle alloc failures in kmsan_vmap_pages_range_noflush()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kernel test robot <lkp@intel.com>, llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, 
	urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=tQ6wJTzC;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as
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

On Wed, Apr 12, 2023 at 11:06=E2=80=AFPM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Thu, 13 Apr 2023 02:27:19 +0800 kernel test robot <lkp@intel.com> wrot=
e:
>
> > Hi Alexander,
> >
> > kernel test robot noticed the following build errors:
> >
> > [auto build test ERROR on akpm-mm/mm-everything]
> >
> > >> include/linux/kmsan.h:291:1: error: non-void function does not retur=
n a value [-Werror,-Wreturn-type]
>
> Thanks, I'll do this:
Thanks!
I sent an updated version of the patch series, which includes your fix
as well as a couple more improvements (__must_check annotations in
particular)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWqf0E0Uo8wA5pdhgpreKZB7TPU-DiyERyG%3DT7bqqiJ9A%40mail.gm=
ail.com.
