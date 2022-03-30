Return-Path: <kasan-dev+bncBDM7RQV2QAERBNGISCJAMGQEWQSUXAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id BB1A54EBDB5
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 11:34:45 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id ob7-20020a17090b390700b001c692ec6de4sf1279548pjb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 02:34:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648632884; cv=pass;
        d=google.com; s=arc-20160816;
        b=XYgahfvfD/h7bOkBswIYt4brhNhGuH1nb5IiBcSZVHs2VU3F6M2o3cEJYSiiBYLw4D
         sLxL/b3gm3fvk6UUcIiogPLFVWkqHn42YCH1rRDLXXA2PPlzMDVrQB8G2uku/kRFLVae
         YqerdsinjL/t6mgTUQ50xhXB5QKn4rThS3IIY5T8ty1EGKNun3NHgTzVQkihtL3uFauQ
         o/8GSkdDXPHK77AdcwO02Bu+I8+f6Ro0AiqTziQqdFPkFeT+eqGeTvfZT2aqca8vsX/K
         QFNyRxZV83yL8MklYC0VglNPAkjfzqo/fdnniLq1NfBUJmMNh5sCxlqovtw9PmcDSBxB
         5ocw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=BOTU0VK1KI/ZqNW1D3JBvrhKukmU3fqtEZsrJ3OXS9w=;
        b=owbapu9GvxlW6hpZg23yZw5MBBFubm8GDVBwZwt+HIjbNhtQb46wv5GbOgEUL1TFrT
         zYbDqIEIHeMuPCvwK6MV7tkpItgore/DERp9n1HzSQWX4X6r52GmULV32wVLR6owsIv4
         uSW5FfBT6TcQcUPmCV2Z+Ks/pf5/3dsV98fQJLvgznZC7+i6inpX2H1DyjURwl4cAcET
         pLQObK2NQlOYDUgJv+SLEJO8S0hxqa4jUTzfTYrMqn9MkndTTkKutqSG+FTsuf84YlXl
         QdfcQReY3mhJWbZlluO5F5Fd2o8Or3EejzY/i2kHFh1/awQPhgk3LXtlEvYWIoPpjTd7
         XhdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=noQDipWh;
       spf=pass (google.com: domain of moubarakgoumpougni@gmail.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=moubarakgoumpougni@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BOTU0VK1KI/ZqNW1D3JBvrhKukmU3fqtEZsrJ3OXS9w=;
        b=uA9ZH0lHDejlELRz5EK4BoJNtleFHMKGPdcPNA477LsAqfRXtIHVZR+CYUVL464oH3
         Wh47v2RoZGdmTq1jswDzcFa2Ju90tZ906M+RC4pI61lDqqtRCMYf3e2EIcO0/Ls6ZAHC
         ktJUeqYgaIu/tz8gJf2J5bLJD3M7RU1Nb9BXwtn0/74lFWzPHa7sRUl5k3PV2wQzYe+G
         ObQAOUjTazPTi1lLD83uFeI/Pkw8JVeW6vW4hvLxp6sZgI0c8G1cVGC8rQ6ie/NdU5if
         GQ+msnvG/xPqCp/X5/8Gxvxm9BRj+mVIsgE/boSQRAbS/oXcGVvkRYzvYY2jLnWF/bJJ
         SoSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BOTU0VK1KI/ZqNW1D3JBvrhKukmU3fqtEZsrJ3OXS9w=;
        b=YIGVXrgLN67vhYo1e2Kc6X+QVHyzT/NlNxnmfADg+GcoquM7KiD3eU8zm+yswDL52n
         VIjLqCf08fIpzKWuPP4tTTYJ7kSdaxQUja9qNWW8LJvk2+nNjZrAMZdxPncVye6Ua4g7
         UANL6XgBx+HImlm4629474+25G4ifAjoTF0Hd+CudUjeXTnBo79qW+wAnIc1xu9C0RW0
         8A0HCysMgLJNG03lZC6EHkTu+/jaCKilffRJlh6J9ysMr3CVvANW2B1Sni+3v7BOL1Ti
         7/p+z6rUbVf1YZl7S+Drf8Om3D5R7/pP0g6pffuWCxxbt2Ga56RAfz88qxE5xori1O5i
         mLLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BOTU0VK1KI/ZqNW1D3JBvrhKukmU3fqtEZsrJ3OXS9w=;
        b=xZdcOdANrJqSYVqirhMGNY4YNOCez0KC9uvTBUNYaGc4rMk6ebfkXTRhNipFzW6kij
         5wbpWKFzYbTVUmpoIlfwlBvtFgsW0tcSf84LlwYtyNRUNjf+xVC2wEk3FHl7AE4RTL66
         aOChnzEgS8MXWOV8N8sG62ty7V429GaUASGJQXoS9xrgjEB7U+6Puyqr+V0//bnR2vew
         AOlhujfCbVKsU2npyrjTslH/v3yc0TGzDaei0HXYoP7DMWKSAf4gnfaU1ca6iqnFubUI
         1jWPYQHzBg6q7gQ3AKnXCrboWjoxJKSH2cJipZgu/T7jspg2FONGxH4KCurJ163Bh+Tv
         +LiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MIHC294x43j0nUhP53ZrgwvfufgsPe38jGHa3pwNRAQUehFT2
	p9jKpE9Ffo4M1hjHEKNvqO0=
X-Google-Smtp-Source: ABdhPJzagkk6qGRhAFxF+NBv1TZr9K0LE1//RlwtcYGgf9gGBzy+AdMq8y1x5MgOJiRlf+WAjIXhYQ==
X-Received: by 2002:a17:90b:3907:b0:1c6:a16b:12e3 with SMTP id ob7-20020a17090b390700b001c6a16b12e3mr3946025pjb.157.1648632884336;
        Wed, 30 Mar 2022 02:34:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5d0:b0:154:375f:9af with SMTP id
 u16-20020a170902e5d000b00154375f09afls1384675plf.5.gmail; Wed, 30 Mar 2022
 02:34:43 -0700 (PDT)
X-Received: by 2002:a17:903:2285:b0:154:c94:c5b7 with SMTP id b5-20020a170903228500b001540c94c5b7mr34839524plh.64.1648632883592;
        Wed, 30 Mar 2022 02:34:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648632883; cv=none;
        d=google.com; s=arc-20160816;
        b=uE6RilKOY7+ahRrNzGomzegZJaRgItsW/Vb+vVCZGfFZ5SRsbnIXBqjB7I0DWAJ+Z9
         wuqQXaiVzqkybuPc2p8s5+7x4iVweYsgHJUNl2y6BvTd4d2f7q+Mw4w4mGLcR8ioDs33
         cZkACmHeTBBeRSZ/hWQfNn4o/LSPTA0HX75svjStPg7fySaWYJ1+L4e+p9BM4K4C4EtR
         qlHzOEorh5DMLu7kIk6rab8qkENny12u45U9OurZEvoFeHgUiAe8MHUzcpovPTzXF4sR
         7vhZIopWcdn9MiumiOk91/0BWphBeLcgNaAdBzNv+skLlrBTGafn2F8W2SugdSfjSazJ
         TTFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=WnS1vQBU9mAKdcjiS0YggBcr/W/0ZKRG93TypJwvfqo=;
        b=dANfllHCEd+trOoICIQ9FgTo0M3JPcH1uft7hXt0GLZCThF3jTgA2BhbShWUrwRw8B
         fcDpblesZQMMzgDgMy5bdzemFzMV65M4deLeictEqUVNlSvRv9GuCzMIpWq9ZXHswefB
         iHS21GHbRlc0YziB1lcl29laMSWXS1zEbUUtoxACmEIQtUGj4COAS+/YCRZBhGV+Ppgz
         spsrCF+xbGr/UJQQf3iQFayTNUdC3WxHgDDAP7czCI6tW6TUd8cW5PB/+F+yB7X14Ebj
         N4LCsN7mVqW+PLrXbhBXlG7uddj6y9bsxYizXgLc60RsppskUSU7k3gH0t+nMwi+DA7J
         sucQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=noQDipWh;
       spf=pass (google.com: domain of moubarakgoumpougni@gmail.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=moubarakgoumpougni@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id q3-20020a17090a2e0300b001b9932741a2si295007pjd.0.2022.03.30.02.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Mar 2022 02:34:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of moubarakgoumpougni@gmail.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id y142so35932454ybe.11
        for <kasan-dev@googlegroups.com>; Wed, 30 Mar 2022 02:34:43 -0700 (PDT)
X-Received: by 2002:a25:cc08:0:b0:63d:2c6d:162 with SMTP id
 l8-20020a25cc08000000b0063d2c6d0162mr160162ybf.137.1648632883325; Wed, 30 Mar
 2022 02:34:43 -0700 (PDT)
MIME-Version: 1.0
From: Sarah Riterhouse <sarahriterhouse89@gmail.com>
Date: Wed, 30 Mar 2022 09:34:19 +0000
Message-ID: <CA+u5MaG-kqkXmCKgLWQW2XXWr2axcyx3V3fp0-EE+pDJmF1Zjw@mail.gmail.com>
Subject: HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000602be905db6c41f7"
X-Original-Sender: sarahriterhouse89@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=noQDipWh;       spf=pass
 (google.com: domain of moubarakgoumpougni@gmail.com designates
 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=moubarakgoumpougni@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000602be905db6c41f7
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=E6=82=A8=E5=A5=BD=EF=BC=8C=E8=AF=B7=E7=A1=AE=E8=AE=A4=E6=AD=A4=E9=82=AE=E4=
=BB=B6=E6=98=AF=E5=90=A6=E5=A4=84=E4=BA=8E=E6=B4=BB=E5=8A=A8=E7=8A=B6=E6=80=
=81=E3=80=82

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2Bu5MaG-kqkXmCKgLWQW2XXWr2axcyx3V3fp0-EE%2BpDJmF1Zjw%40mail.gm=
ail.com.

--000000000000602be905db6c41f7
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr">=E6=82=A8=E5=A5=
=BD=EF=BC=8C=E8=AF=B7=E7=A1=AE=E8=AE=A4=E6=AD=A4=E9=82=AE=E4=BB=B6=E6=98=AF=
=E5=90=A6=E5=A4=84=E4=BA=8E=E6=B4=BB=E5=8A=A8=E7=8A=B6=E6=80=81=E3=80=82<br=
></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2Bu5MaG-kqkXmCKgLWQW2XXWr2axcyx3V3fp0-EE%2BpDJmF1Zj=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2Bu5MaG-kqkXmCKgLWQW2XXWr2axcyx3V3fp0-EE%2Bp=
DJmF1Zjw%40mail.gmail.com</a>.<br />

--000000000000602be905db6c41f7--
