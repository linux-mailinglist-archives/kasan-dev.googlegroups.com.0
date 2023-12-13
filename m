Return-Path: <kasan-dev+bncBDYZHQ6J7ENRBVGK5CVQMGQEFNEEC3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8481D8120D8
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 22:42:46 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1fb1f23d1bcsf12482495fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 13:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702503765; cv=pass;
        d=google.com; s=arc-20160816;
        b=bFbF66dMYy0vmGbXyaU7S2kcGWBaeRNrzV35NWI7DWf4neGc8+n6KKn0d0EliYAR7r
         TiL91iXQ35W0tfkhZJ/ZjuOHzDaP2G9EHiRF362CRNl+26bIxoS2cuQSOMa/I3n1+/bx
         ZAxPoxxWAgdi9CzCJpWOZGlAC5My7cx7WYFIRyES+0q/F2Oc1eQv007uJ2ixD2eyV44T
         KCRve5hQIzPw6PkzPLXScHknOgV6VLV0fJ9gQgIUeFYlygZeQmNKPvTYvhbNzlhKsvy3
         JfjjBus2oz2sJgDuyzkEmClMYyP+FOTHTUwI791F/yizwEpT0cqLw22pdHazjAbLWPnC
         FRsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=1inS31zr5++JwCkavNfw8MegMdkcFf6VVfU/B4+BlN8=;
        fh=PCd4oB7lltsZ3rRh9Uwm8luoLEfLd0fPYgQXCkhrP5k=;
        b=cdHdzeH857lSMfqTa6U+tov2c6uKpxqzfPfqEEQjH+L3/SerRoF8iBID0dKlYBS+4W
         SaMqcGlX/VGj0CKlkyIKC/5WxpYmKBv7w1g56bm/EO9CXzoQUm7CrJY5/tnT7gmHYta4
         HBAW3RddeG2EZxLKSaDtxg2XTiVUnj3PpNXPWQckKwNbixfdg/9jPb0/wNnvcvKCekFu
         ro9ajBd2CJE5st1gTQsdbkGxfECQQxSEPVmS6BXNKR7rGhVAkZq9QgOjLeumXbapEE9M
         5qPAxLLUWHRvyvNzyU7bsR/QXun6uMs+uAUi2j3NpGTkcjyHsNZb6YYwK7JK6OMoG8Uu
         w0Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iC04CCUD;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702503765; x=1703108565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1inS31zr5++JwCkavNfw8MegMdkcFf6VVfU/B4+BlN8=;
        b=XdRRxsd+gVxaS2+y5QPEtEev9q4CBShH45Z/9xsaHbXm2HD1k+THtWH26oNTrAU0vu
         aNpCQVIJSmOY+HH/VNxqXhHW2jQNerQIgp1MvRFx2GMSHMU3CoP/npaJnab8+L+aKRQe
         Y+gt4HRxzubXtFJPaqUqKYsswzwnhKujct+EHod9p6AO1WLXrpReLRZClGKuX1+o5cie
         FUVJBG30DUoCm1/DKa4xSGNWVthmbagbjfAFqRSocLhMTkcPvPIzpJReWKoDwqSej98g
         aiQRfIytSXPhMT/yQ5CaqPJrjdy6EWCY7R4hztzVI1Tdjwh0bc5jlbosZKn3TBPmQThl
         +SBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702503765; x=1703108565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1inS31zr5++JwCkavNfw8MegMdkcFf6VVfU/B4+BlN8=;
        b=mIHbMx9mOgOb2iSwtMZN+To4yDrYqGKTnTUKImHurQyn3/40isFIKhpxKkVQ334mDh
         EIAlNT8RCwfakftbkesVZlq+eqllSJcHuq5yX/If5Fqq9iDXsCZNGdT/mFWpExT8B7K+
         vU1m3v9TRWvPzMSdML5BZuLX+9kMviSv+OxLRcoxfkmR7Ute04lajdZSg82RhBXFJPJD
         aFmcoYNUUXTjpgpeBEmrkijtjfdc//wI9+VWSspnTk5jMK6Rz94L9eWbEXGZ1EbBQv4O
         RxjqCkJZDDahje8cGi2bWEIMpoFDcOpRQha23At6K7taCVAgGDhahL9Zlgidq8ndSHR8
         aPSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yysarsn8FXc87ikc2Ravwf1iG29S3NZHhy/jrlsOhWXvJ5eyhoH
	dlfbrzkezuodtJK/rN0A7E0=
X-Google-Smtp-Source: AGHT+IFRTjJVONW0vFrg5Lpw0aoKmlHhsmBjqipZUrh6CADLRMSbDGbI57elSQTgK2Jq+0AEKL0BYw==
X-Received: by 2002:a05:6870:ac06:b0:203:10ab:f237 with SMTP id kw6-20020a056870ac0600b0020310abf237mr2664591oab.33.1702503764967;
        Wed, 13 Dec 2023 13:42:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e15:b0:203:3b8e:507a with SMTP id
 mp21-20020a0568700e1500b002033b8e507als391052oab.2.-pod-prod-03-us; Wed, 13
 Dec 2023 13:42:44 -0800 (PST)
X-Received: by 2002:a05:6871:d216:b0:203:1833:bb0a with SMTP id pk22-20020a056871d21600b002031833bb0amr2471090oac.34.1702503764231;
        Wed, 13 Dec 2023 13:42:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702503764; cv=none;
        d=google.com; s=arc-20160816;
        b=w+YjQH92ll3hBhlOm9YuzMGal8VdnCtBlcJHCfZFICww/ZYwAcyt82uVBExFj4MyDM
         CCgVBQlHJQ9eI5w5O+Y+1Imp/Pzs82e7kN1SP9kMqTUIO4yB4v/UTlxDcTdvv3+ebmGb
         LPHssCmS1GAEoRn/L05wh8Ya35p+tTbbAiUXIXycw7alUFR4ugiUwXt7Uiq7tod2T1p7
         fCZEVzrTj5/r834Fu4eKWzZsotkrMXOI9f40riAHZwL7jyurDqmFATiNIVX4IXSa/LT6
         bSrgVpYADVqVVmYX54Bsk6qthm09o33qk8jJXoAS2xsT00C0FH33pCnCH7yMefEnQFTP
         OogA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fdKw+cJKuYBtq2AfhtjjClQUyyHxxJix2Fa9xvak1zc=;
        fh=PCd4oB7lltsZ3rRh9Uwm8luoLEfLd0fPYgQXCkhrP5k=;
        b=eNYrNGs8AjI9RntPm2I9l644duiGazw8WtLQolXk8pOjbhlukYJttDgcLbAWs9rTdC
         QjcwXp3T45W2IzYvoAiJyem5vMwpEKvPgaKNvb6+BfbbHUdnCCcgInXPnvQ6q8BvC3TL
         oppyuyIvC2nciwCU3CfyHWIR5JDJZaNRMVxgDG/8RD0irdadgop94zXgf4UFZWZINrqa
         OqtwRg4KqUniqeqsIk1LMjEczxYGxefziM9Ae7m3iyAaau6lH2NagjigHu2Y97srzJLU
         rXJOCjl4GoAPoFTqjtfX7iz6NEyTROumFLhOukuo2ahOMmi2OPEzOMwZwbTuhLWgtwHf
         Jgmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iC04CCUD;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id lu3-20020a056871314300b001fb4d96efc3si2270oac.5.2023.12.13.13.42.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 13:42:44 -0800 (PST)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-yw1-f199.google.com (mail-yw1-f199.google.com
 [209.85.128.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-138-tSHZ90RMNySCCAKL0fgE9w-1; Wed, 13 Dec 2023 16:42:42 -0500
X-MC-Unique: tSHZ90RMNySCCAKL0fgE9w-1
Received: by mail-yw1-f199.google.com with SMTP id 00721157ae682-5ddd64f83a4so61534127b3.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 13:42:42 -0800 (PST)
X-Received: by 2002:a25:1342:0:b0:db7:dacf:4d5b with SMTP id 63-20020a251342000000b00db7dacf4d5bmr3860235ybt.87.1702503761254;
        Wed, 13 Dec 2023 13:42:41 -0800 (PST)
X-Received: by 2002:a25:1342:0:b0:db7:dacf:4d5b with SMTP id
 63-20020a251342000000b00db7dacf4d5bmr3860229ybt.87.1702503760942; Wed, 13 Dec
 2023 13:42:40 -0800 (PST)
MIME-Version: 1.0
References: <20231212232659.18839-1-npache@redhat.com> <CA+fCnZeE1g7F6UDruw-3v5eTO9u_jcROG4Hbndz8Bnr62Opnyg@mail.gmail.com>
In-Reply-To: <CA+fCnZeE1g7F6UDruw-3v5eTO9u_jcROG4Hbndz8Bnr62Opnyg@mail.gmail.com>
From: Nico Pache <npache@redhat.com>
Date: Wed, 13 Dec 2023 14:42:15 -0700
Message-ID: <CAA1CXcBdNd0rSW+oAm24hpEj5SM48XGc2AWagRcSDNv96axQ9w@mail.gmail.com>
Subject: Re: [PATCH] kunit: kasan_test: disable fortify string checker on kmalloc_oob_memset
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	vincenzo.frascino@arm.com, dvyukov@google.com, glider@google.com, 
	ryabinin.a.a@gmail.com
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=iC04CCUD;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
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

On Wed, Dec 13, 2023 at 7:34=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Wed, Dec 13, 2023 at 12:27=E2=80=AFAM Nico Pache <npache@redhat.com> w=
rote:
> >
> > similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
> > FORTIFY_SOURCE") the kernel is panicing in kmalloc_oob_memset_*.
> >
> > This is due to the `ptr` not being hidden from the optimizer which woul=
d
> > disable the runtime fortify string checker.
> >
> > kernel BUG at lib/string_helpers.c:1048!
> > Call Trace:
> > [<00000000272502e2>] fortify_panic+0x2a/0x30
> > ([<00000000272502de>] fortify_panic+0x26/0x30)
> > [<001bffff817045c4>] kmalloc_oob_memset_2+0x22c/0x230 [kasan_test]
> >
> > Hide the `ptr` variable from the optimizer to fix the kernel panic.
> > Also define a size2 variable and hide that as well. This cleans up
> > the code and follows the same convention as other tests.
> >
> > Signed-off-by: Nico Pache <npache@redhat.com>
> > ---
> >  mm/kasan/kasan_test.c | 20 ++++++++++++++++----
> >  1 file changed, 16 insertions(+), 4 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > index 8281eb42464b..5aeba810ba70 100644
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -493,14 +493,17 @@ static void kmalloc_oob_memset_2(struct kunit *te=
st)
> >  {
> >         char *ptr;
> >         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> > +       size_t size2 =3D 2;
>
> Let's name this variable access_size or memset_size. Here and in the
> other changed tests.

Hi Andrey,

I agree that is a better variable name, but I chose size2 because
other kasan tests follow the same pattern.

Please let me know if you still want me to update it given that info
and I'll send a V2.

Cheers,
-- Nico

>
> >         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> >
> >         ptr =3D kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
> > +       OPTIMIZER_HIDE_VAR(size2);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, size2))=
;
> >         kfree(ptr);
> >  }
> >
> > @@ -508,14 +511,17 @@ static void kmalloc_oob_memset_4(struct kunit *te=
st)
> >  {
> >         char *ptr;
> >         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> > +       size_t size2 =3D 4;
> >
> >         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> >
> >         ptr =3D kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
> > +       OPTIMIZER_HIDE_VAR(size2);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, size2))=
;
> >         kfree(ptr);
> >  }
> >
> > @@ -523,14 +529,17 @@ static void kmalloc_oob_memset_8(struct kunit *te=
st)
> >  {
> >         char *ptr;
> >         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> > +       size_t size2 =3D 8;
> >
> >         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> >
> >         ptr =3D kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
> > +       OPTIMIZER_HIDE_VAR(size2);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, size2))=
;
> >         kfree(ptr);
> >  }
> >
> > @@ -538,14 +547,17 @@ static void kmalloc_oob_memset_16(struct kunit *t=
est)
> >  {
> >         char *ptr;
> >         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> > +       size_t size2 =3D 16;
> >
> >         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> >
> >         ptr =3D kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
> > +       OPTIMIZER_HIDE_VAR(size2);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, size2)=
);
> >         kfree(ptr);
> >  }
> >
> > --
> > 2.43.0
> >
>
> With the fix mentioned above addressed:
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAA1CXcBdNd0rSW%2BoAm24hpEj5SM48XGc2AWagRcSDNv96axQ9w%40mail.gmai=
l.com.
