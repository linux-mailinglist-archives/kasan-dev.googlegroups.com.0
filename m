Return-Path: <kasan-dev+bncBCPMNRMB2INRB7G272FQMGQE3EM6KFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D4314415C2
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Nov 2021 10:03:58 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id y22-20020a17090a6c9600b001a38db472c0sf8652446pjj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Nov 2021 02:03:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635757437; cv=pass;
        d=google.com; s=arc-20160816;
        b=PqjpmmPQ/jqrF8xjUmmnPC0//9aRy26ntDmot7EfX7QpVt59uK843Wo4YLzLPTgKCQ
         CHdm+BTyoMOuOKAWg6bdRgTiTe8037wtNiaEhjxX0iMmeBt9N8HXKITmLcZk97F3LC6o
         rrDb0qcty5gkjPr3gNzFyWOkG3LtcsW0UP+h6/nEr+i+hlxlcKu3e+KYsMuYlr9bKbmV
         zkSKUdDrB7AYHKzTXOej4UpYC+VpXEYG9ygjqUmBgTDb1Y+WjFg1D23UNyhRbsth2nZz
         r1+iPNtpJiry3v5fVvYFSNjD6yoEp83cTiwKFu5w5pijAas8aibUREzTQHagt1gZHkve
         /S3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=JNEJ+5PXvDpfMEJcDiGLmsCUDX/527bB7MSkendUjWA=;
        b=k1D85OD1Pw1sgpyhGm671aOmuopskIJ29Yy9QKU43mITHwusgA4fORVB7muAeVD++v
         i0WAw2jGrbv28wlS/JQ/dz0g93FIJxwhUu2PuLTNznk6q62cc8SDytJfFGPSOeZpX4Ea
         du0JCNbVVOn6J8fNSRfQBNhUzV2ha6kLpZPL7rNEgC9RD/FlxsQipYcXNvrufC/vw02R
         3HxpmrYNzigM3NCRZb6bjSAhNsrwSA5X+4x4rZbYsajtb/ZgVY9wUUZV19abInAR/759
         Bj5iB6wTFyNOS07+TVLKhoRz/4fOZ/08BF7EOaCeksYh4PUKoF9WwtgdBUKvG4zeGTbV
         hQlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DvVHT4sQ;
       spf=pass (google.com: domain of planetbeauty61@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=planetbeauty61@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNEJ+5PXvDpfMEJcDiGLmsCUDX/527bB7MSkendUjWA=;
        b=KF4nWUQM9dzkCSusAl+eAf/yX9mwv/zMlPKmpkXBSAT7vG02u7Mj546dAoGreh5i+g
         dwC2WCks7FAiUHJsMLnoWDNDU/j91HBXOUq4nAcMwxz/FQHtrXb473vfzIPeGrFL2g7U
         Tzw5MbE6SKZLDOi3W/phL7ECsy6zzo1kAJuqZ5I/eZi140qfZNkhxf14yYqQxVcxGMEZ
         TQcI3IucMY5Hi2mCk2ykM7bmjoUVD3Ojx8HU/FCpS9kahBvkhdlcbUJAagr1KWwRNKUQ
         A0R49mRCN9IJIwVMFto1ZTINL019hprgBj1mP5zW4eQmEBOuxMoQwsVO5ltVMjfXswRx
         Ak8A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNEJ+5PXvDpfMEJcDiGLmsCUDX/527bB7MSkendUjWA=;
        b=fnzmrx0l9+Xrie/AjRJea7rikht4bO8QSvozmi5gbsNMcL6TM8VKj7DHCyoMuF+qsD
         jOG0Qp1t5ff4pJ7GYwgWbTp7s3Ahf7XYANhUJGsIN7gMKJwwiixkEHalzrfh3QudO04+
         pq8vJJKLmPt78b0FxObnG0tNQdC0gOXFUJ8YEDNwdeoCmIokzr06f+rvLKJiu3F5YYd4
         QI6w8RpJHvPKeApqNS2T4AXnAeOELTf6oayYTXJCcR7YaGtGyUW8DtRzQHuZqKCli/vT
         k3+dFQQruSzJuPBJrquudd4Kn7D8zgxIB0NyAZKjF9SHgMJ87lp1FtIkELcPO/5rVUVJ
         kfzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNEJ+5PXvDpfMEJcDiGLmsCUDX/527bB7MSkendUjWA=;
        b=hcZbNFz5EJ81Ee0lq9OiJnqDng0Q0yRQnuEx65ov0OlOKYZK9/wtC+jZP/pESg3pSa
         xTUfbNpA5CExOnp28j5YlSm8JjJngdsQgkKFWuciwkjsgvBYKuIPdDU95tMRPHjaZ1bd
         UxTH7Xg0UmsyZY1YIFCrw8sY0hy6TNFtD5IA3jiqBoH2VOlraHDz4eltnQGRRJeVS8fU
         s0kaaO1BfxLsv52OWsZhAZXtw0AeBPZs2dasPUKWhDE3YpNUiPsDiDiBXRFPwp343UQh
         CKx1gzaasAxI3cEifNJoGvCuRJjXkLC+5PK6H/WKF4csDWx7S/79W3HAsh5uppRV9w1x
         YnWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533X09eRJZbYGm6RsCacUwvzClQY2vxe7SqRU46/SQH0m5viK7Cl
	ner6PjdA862O9H7SjIs7RK8=
X-Google-Smtp-Source: ABdhPJy8KWzvFcc3NOVNd/zfvoVzNg9bJMr3EtvD7imHfTGQxQgSoImvKPu1Y/FusSmpLP9ULWDNLw==
X-Received: by 2002:a05:6a00:1897:b0:47b:ff8c:3b05 with SMTP id x23-20020a056a00189700b0047bff8c3b05mr27266987pfh.37.1635757436746;
        Mon, 01 Nov 2021 02:03:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:181e:: with SMTP id y30ls6456116pfa.8.gmail; Mon,
 01 Nov 2021 02:03:56 -0700 (PDT)
X-Received: by 2002:a62:19c6:0:b0:480:610b:957e with SMTP id 189-20020a6219c6000000b00480610b957emr13739028pfz.37.1635757436227;
        Mon, 01 Nov 2021 02:03:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635757436; cv=none;
        d=google.com; s=arc-20160816;
        b=ZbaPM+bWReSaymznGcsFEuUffVkj8VSwf/8kz8zc65wHT/b0W6hCWux96GuvEqcbd7
         hDK+uTgu/KRtLKpP5Ohg2+Zcfc34h2fUpONFsZkBtfbmnkE+rivavw/4Oqwo64fisUOE
         z1hXQ9aeeDGzSiGhdRlUqWyavAn3GSUDlX7iEqcjtZTwt4hnEsk4AZrcnA3djdsYoEKV
         HqGgLBOjpmeu/F9aHTAtck7XKkps7HG6K++dTfU94Rn2F5+6tYNU8hb7YCbgRttoeIZG
         UQCkId5O7B2PBQ75rwYkYHL5kKov7zkZ4pwpVIXKCuBAQcP+TkZxixUdOc1sboLOuaWr
         NYXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=E2mmv+DvZ5O0LPq84pKhjfQ0wv+3JTi0htU9mD6UUdw=;
        b=EOv2eTJQT+4KlegwRni3AUW6EB5EDGDOMY7r/jVqhGvQlHzThda9xKfkA8Xxtt9WjY
         Sz9SBTJ27fwpFo9viA3SVg7GOQ6qXFu1swmTnuJbZl2L8Vdlgdi04s0VxAhkXNAxHXC8
         eUOO+T2Jw2K7ueZMP21ZcPLEpviHBUHL+YDLYmx8xBXn/ndrEv5dzaV96Pf+SuyC5qe/
         zaDd7Ru2rW9t0sNdcX6wRmEc6QZ87LgJTTeoIbJKQ6YSzcgmK2mt/0WzKwv0CVJ5+z6E
         RXH+exRSOd3xueuDhQETWFHmGycEe3+uEGqX/k46O0LynnWDJfjAKTPmaRGPD8NKagKp
         38vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DvVHT4sQ;
       spf=pass (google.com: domain of planetbeauty61@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=planetbeauty61@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id b15si1482613pfl.6.2021.11.01.02.03.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Nov 2021 02:03:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of planetbeauty61@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id v2-20020a05683018c200b0054e3acddd91so24414344ote.8
        for <kasan-dev@googlegroups.com>; Mon, 01 Nov 2021 02:03:56 -0700 (PDT)
X-Received: by 2002:a05:6830:1b65:: with SMTP id d5mr4712557ote.151.1635757435830;
 Mon, 01 Nov 2021 02:03:55 -0700 (PDT)
MIME-Version: 1.0
Reply-To: greytownfl@gmail.com
From: Loan offer apply now <planetbeauty61@gmail.com>
Date: Mon, 1 Nov 2021 10:03:33 +0100
Message-ID: <CAENwAooiYbrjy-1XXFhytS1ahkJL-mDY5S0OmpEP0QMUY5qk7w@mail.gmail.com>
Subject: Re: Reply
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000e6c4cf05cfb6744f"
X-Original-Sender: planetbeauty61@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=DvVHT4sQ;       spf=pass
 (google.com: domain of planetbeauty61@gmail.com designates
 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=planetbeauty61@gmail.com;
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

--000000000000e6c4cf05cfb6744f
Content-Type: text/plain; charset="UTF-8"

*Dear Sir/Madam,*

*We provide loans to companies and individuals*
*with a 3 years moratorium.*

*Kindly reply for more details.*

*Warm regards.*
*Mr. Magnus Bengt.*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAENwAooiYbrjy-1XXFhytS1ahkJL-mDY5S0OmpEP0QMUY5qk7w%40mail.gmail.com.

--000000000000e6c4cf05cfb6744f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div><b><i>Dear=
 Sir/Madam,</i></b></div><div><b><i><br></i></b></div><div><b><i>We provide=
 loans to companies and individuals</i></b></div><div><b><i>with a 3 years =
moratorium.</i></b></div><div><b><i>=C2=A0=C2=A0</i></b></div><div><b><i>Ki=
ndly reply for more details.</i></b></div><div><b><i><br></i></b></div><div=
><b><i>Warm regards.</i></b></div><div><b><i>Mr. Magnus Bengt.</i></b></div=
></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAENwAooiYbrjy-1XXFhytS1ahkJL-mDY5S0OmpEP0QMUY5qk7w%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAENwAooiYbrjy-1XXFhytS1ahkJL-mDY5S0OmpEP0QMUY5qk7w=
%40mail.gmail.com</a>.<br />

--000000000000e6c4cf05cfb6744f--
