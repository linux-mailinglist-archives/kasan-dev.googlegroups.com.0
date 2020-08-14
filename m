Return-Path: <kasan-dev+bncBCGL74GWZMKBBJEJ3P4QKGQEW3X6CCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 986A6244D4B
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:06:45 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id e2sf6855633pjm.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:06:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597424804; cv=pass;
        d=google.com; s=arc-20160816;
        b=qEDh4+Nw1Rz3L7S0H+kDlOZlT6B560zD3WMZP3To8Iz01ecjp+E+NSX5957u1/kvIw
         MWXDqThVwUUtZ0yUmM5btDj71uaTFB/U3hBRG99srxjhnR+cFS54XzeIpixTdBqjooQ3
         J3ofNu+LEGjBqYMP/Iklw3PUQPol+l0anjxUo3VpY+asNBc/AUqDGGkuIE649B+RGEUu
         2uiMsoy00TIdWLuvvbEc7pSvyphbx+TVRiEysJhiBApxHD1OBHWuPGMbyIl1O1pveDZ+
         3eBmu/XIecoBY47+bNhtTpBlnEGQS6KkkHBTMDM3ezvXvXqRvZSVs/OiV7uUyW7gZnMw
         N5tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=X9dX12uepukJa+4XmRmm+BH1yXKTRhthHsNAUDIoqdQ=;
        b=hoCQsygmDmNUxvMDz6RdFLWo0lVFjGBQOQAg6fcNRu/wARvoZ10zxwgead2xBdXoSX
         VJIoVotbRSAavo0dCLegrFpEhI5CdADz0N0QC1OIWSIU21aHZBr25Ti9JJe80rIXaBH+
         RJTgyAzER3BS5X3ZJbpfFXU6fpsYo6RYCFk+poW8lbX8jR4VXi1xs31VwF2LPlg1pQIU
         G75SYM00u5ClkcWniGMOowX2+/+u6g84HvFfS+761LRSrUxNapjkM3mXA87txQ8J+JfG
         wbVnnhuh5AQLTlywEMLKXB38Pfta0VmquybwHUPHukTkxA8NDhxDx5O4/vYOmS5B4gBB
         SpAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="uJB/yuKB";
       spf=pass (google.com: domain of aishagaddafi1985@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=aishagaddafi1985@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X9dX12uepukJa+4XmRmm+BH1yXKTRhthHsNAUDIoqdQ=;
        b=r3Wwz+/HckZAI4cR6fzuhzPHorYVZ1GfddkbqdkvsIbTpe8uZRmP97mgZFEmA+3DWa
         fhmUZL42BQTYc03xsH4mCXiIy3B+I0YMw6ezIHymT1CCTxO0FtX7aKr0D2swGgP0YUDK
         DEXxy/o4ONT229wgu8J33cneLkRPjwOB9Wtzbp3QjP319t9eiPU7z+KWYZmxjrk9N0Bg
         8YSFXQN+4j/vsRNX8vLfxw3wm64eQpQIT8tqRjYnEgBa9DKftwGe/WaUzJLVb1kvAVs6
         hYxiNjohUIc9XUz2OGTlPup0Pc5wpe9bRjjf1sfodPPh1q9In8kPzlWo3gNZym6M7mk0
         CSGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X9dX12uepukJa+4XmRmm+BH1yXKTRhthHsNAUDIoqdQ=;
        b=ZpOo8FezmNen3hJYyFj/+EOUjm7nHSPXSJ0qjTXz/571p+pQ+oF6o7XBnKXFfPk+as
         uvsO//06VfaeMdXYZnfZc/AwC5FXZqWYBSVdZeXmB7jRw9XYSDRstp8XXT3DcJpdPuWA
         5ABP6d92BxZkPuTBxTgiJGI0zbfh3bgNmFR9vHut2GQdLixY1SoD/aR0fEdIqe8x67dP
         US65A5iMFkpNkMtPTgz7D0oelgr6HJtbHQOgukszOcYkTb0JWOpG+UsiKb9quNtKI514
         o2TKUwwySxCZhSiIg1PbkyTgUNY1GfHUopmzwLizrJpQ7UHOL4ShiG3IvfObM3YjpDdW
         kpMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X9dX12uepukJa+4XmRmm+BH1yXKTRhthHsNAUDIoqdQ=;
        b=VOYw3j49edvhG54qMp5wjNYwiz7jNee5b0VH9/RXEO2hixRlS1VbBNTbVvsCsxfyRi
         Y0E9g8k2/74QbxR8wKscSDkDbj5CZsiyIAs3KPNmWszi6J6WhPJb/FQr0ZVswjqpkula
         bqsF+KutyWbzykmjlbXmG5JNcErk+nfqJHCrwgw4vJfDwpDJEipw06cHaJnd5oLAnohK
         tCZNI3eg0aYizTaNXF6Qd+90yhYrPA67AsoJMnL6mu31AM0AsuwLNTpj65EyLosQZYEc
         juIrdI5eNC6dEOrckIOWCLGDSrNKSTbYSwxF5B5iFiqAbx30a9HSdgePwJB0uoZrbCXT
         dU8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/OxntFE4MO1NHmnrdBb6aJulJby0Pcgk3qGX8p/dw/3fd8+td
	ayZqM/x4iThAkm2fnLJ3OFY=
X-Google-Smtp-Source: ABdhPJxMrua2lneIXsbDKsFSdtvjKEZayzdvXKGHTZMQ778UyKQsikVX4T/JHND5zacM9YVKPXiC4w==
X-Received: by 2002:a17:902:9787:: with SMTP id q7mr2789387plp.0.1597424804287;
        Fri, 14 Aug 2020 10:06:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:620d:: with SMTP id d13ls2671623pgv.0.gmail; Fri, 14 Aug
 2020 10:06:44 -0700 (PDT)
X-Received: by 2002:a63:5160:: with SMTP id r32mr2499957pgl.112.1597424803865;
        Fri, 14 Aug 2020 10:06:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597424803; cv=none;
        d=google.com; s=arc-20160816;
        b=DiZSDFEwokdqL5IhqAHnisz8Jo3EItlZERUP2hbmnZcme7BXCbF+p8lgO7BDkfxRDv
         AHobDvK7ewIcLp/DwarviVdkOenH7LZ+ZUb1k/pgV+Lgq8p1SEaQzFfWOzqxI3FQrU0v
         vmTtZgDT3DnZqtCO7xSSdL6XhLKljh8q9YYKPyibzoiQ+jweDocmC+IK1jIlWa8OZfIs
         AyhZixunLXAaIHV1zVmGHKje2WD7ZlCKg/sUpkoC4d+prH3jhNSmPdelCzh3kWZL+za4
         o9FDTGzjihogWlD9z4Tt/Vu/rOxtokQDNojjcHs4HdWt0zIIHfhtfKxAyOLrogYRG6g4
         EMMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=N1tTWlhA9rTJYySnhWezy5zQ7IOHeeq8UmCduEGk7R8=;
        b=MQtKunM9BgUJ7mJYhTj6jHp34EidU3l17NClI0AvG2THOZ7GR4/8l6pcjWU5dxihRs
         H+5B6nosTABdzpT8EzamlzBEt14Qlb5gl/0E02LvjLd971/qBbDu7DJa7mX+5+rCwTxM
         W/7BF0bOl14dqqZeCHcdSkyLxno+/c52N6LK28b/aNi/hmpM36dfhuVDlXPo3TTPQgEf
         SzHGrjy/gMRJcdZzuoFCWUJ3DT6rXcijZU1cc5mDVHY+Sk3pa0ydDRfsNHXmg3Gkn+Q9
         oiYOchChjUju9Orgu+gdx0xfVBuOy51RofwR1ZFRgweVYdb6Vqw2lu+xWvpth0ejob3j
         gQ2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="uJB/yuKB";
       spf=pass (google.com: domain of aishagaddafi1985@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=aishagaddafi1985@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id v127si440034pfc.0.2020.08.14.10.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:06:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of aishagaddafi1985@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id t6so4832967pgq.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:06:43 -0700 (PDT)
X-Received: by 2002:a63:304:: with SMTP id 4mr2231063pgd.296.1597424803512;
 Fri, 14 Aug 2020 10:06:43 -0700 (PDT)
MIME-Version: 1.0
From: aisha gaddafi <aishagaddafi1985@gmail.com>
Date: Fri, 14 Aug 2020 17:06:27 +0100
Message-ID: <CAHsHYwdW92LERRuRXOe9T7MoH_UVFsqTU8e-WF9zfD3KcaFw+w@mail.gmail.com>
Subject: Dr Aisha Muammar Gaddafi
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000f807d705acd971b1"
X-Original-Sender: aishagaddafi1985@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="uJB/yuKB";       spf=pass
 (google.com: domain of aishagaddafi1985@gmail.com designates
 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=aishagaddafi1985@gmail.com;
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

--000000000000f807d705acd971b1
Content-Type: text/plain; charset="UTF-8"

 As you know I'm Aisha Gaddafi the daughter of the former president of
Libya late president Muammar Gaddafi who was killed in the civil war which
took place in the year 2011 which ended up his life on the 20th October
2011.Before the death of my father the Late President of Libya he made a
deposit of 10 million US dollars with a security company there in Ghana .
That no one knows about except we the children and now my brother is in
prison for trial for war crime so i am the only one left out and i got an
mail from the security company , that i have to come for the funds but now
i can't because After the death of my father the UN and Libya Government
has been tracking all my father's wealth and money everywhere around the
globe my dear but, this was the last deposit my father made before he
died,so i am looking for a trust worthy person to stand as my foreign
beneficiary to help me claim the funds and i am ready to reward  whoever he
or she may be and i will also let the security company  know that i am
appointing the person as my beneficiary, and help me receive my funds from
the security company  so i can come out of my present ordeal and to go
somewhere to start a new good life somewhere my friend....Please i will
love to read from you and let me know if you will be able to help me with
this and i promise that this transaction will be smooth and free there is
no need to be afraid and please this must be a secret between  both of us
hope to hear from you soonest.

Best Regards.
Dr Aisha Muammar Gaddafi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHsHYwdW92LERRuRXOe9T7MoH_UVFsqTU8e-WF9zfD3KcaFw%2Bw%40mail.gmail.com.

--000000000000f807d705acd971b1
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">


<span style=3D"font-size:12.8px">As you know I&#39;m Aisha Gaddafi the=20
daughter of the former president of Libya late president Muammar Gaddafi
 who was killed in the civil war which took place in the year 2011 which
 ended up his life on the 20th October 2011.Before the death of my=20
father the Late President of Libya he made a deposit of 10 million US=20
dollars with a security company there in Ghana . That no one knows about
 except we the children and now my brother is in prison for trial for=20
war crime so i am the only one left out and i got an mail from the=20
security company , that i have to come for the funds but now i can&#39;t=20
because After the death of my father the UN and Libya Government has=20
been tracking all my father&#39;s wealth and money everywhere around the=20
globe my dear but, this was the last deposit my father made before he=20
died,so i am looking for a trust worthy person to stand as my foreign=20
beneficiary to help me claim the funds and i am ready to reward=C2=A0 whoev=
er
 he or she may be and i will also let the security company=C2=A0 know that =
i=20
am appointing the person as my beneficiary, and help me receive my funds
 from the security company=C2=A0 so i can come out of my present ordeal and=
=20
to go somewhere to start a new good life somewhere my friend....Please i
 will love to read from you and let me know if you will be able to help=20
me with this and i promise that this transaction will be smooth and free
 there is no need to be afraid and please this must be a secret between=C2=
=A0
 both of us hope to hear from you soonest.</span><br style=3D"font-size:12.=
8px"><br style=3D"font-size:12.8px"><span style=3D"font-size:12.8px">Best R=
egards.=C2=A0</span><br style=3D"font-size:12.8px"><span style=3D"font-size=
:12.8px">Dr Aisha Muammar Gaddafi</span>





</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHsHYwdW92LERRuRXOe9T7MoH_UVFsqTU8e-WF9zfD3KcaFw%2Bw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAHsHYwdW92LERRuRXOe9T7MoH_UVFsqTU8e-WF9zfD3KcaFw=
%2Bw%40mail.gmail.com</a>.<br />

--000000000000f807d705acd971b1--
