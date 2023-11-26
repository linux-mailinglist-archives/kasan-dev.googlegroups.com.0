Return-Path: <kasan-dev+bncBDALF6UB7YORBKPKR2VQMGQE2JD3EUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F7BC7F9572
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Nov 2023 22:14:19 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-285c72486edsf466284a91.1
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Nov 2023 13:14:19 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701033258; x=1701638058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DjowUfos9YkHQS8XYR7U8NYVE0qKLVFWwsvyxMv6TnA=;
        b=CH/e+aO/nmBmlby1JTj7Rgaj41wql3W2gGjRX4mzliDbK9ma/i/BVddF8BzejnbiC9
         NysSc6bgihrkb85EWsgJERaffSS1i827jsnwQaUCeIog5lc8YaRvRkz/+GkIyiAZbr1U
         6vagj0csa3HBG2PFrqiQR6KxqhzCpmPKxQ/v02P0pNlNjzRwdqPmtvvVFfkXP+hNBBGY
         5vMEgvV1Jre3BrjMof20dqy+FUv4KHa6QFmVbMQPePBVPCQrpn2c12LVyltwAhjt/G1G
         NUTd3p3elzZJmyu2jKol6S4m6T1AG/m0y91op4UMIRksutPWWYlCk7CjzgbTs2RCnaCq
         uORw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701033258; x=1701638058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DjowUfos9YkHQS8XYR7U8NYVE0qKLVFWwsvyxMv6TnA=;
        b=S7BJQVrIkuXcoK/zZxTcB3whKb+wtPq+2k8qdPsRujT5LitDGtE8PyrgfhNoic1+Of
         OUZB3lSp+N6McwTOMLdK5aMFETiJd7gOAGSJD5JSyyGoAskJc4JNfSOtCzobnpW2+5ZP
         ZNdzbbThgMMfx/7bi+SvH1vhC65zooLSKLrBY7JWDcavGFWLqUPyaJxitMq6XH73rinD
         87Bam0XQAVXoQmXPEyah67zwkbIEYRf5A+hUBX4uHulrWr21K1wesJd6EJXT020e6VXI
         g57slRhNlCW1tO5eMuf7elPZ3kBpMh831SJ2EoEFH3zrY0GyUmPHExViZyR5gNLMESbe
         u4CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701033258; x=1701638058;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DjowUfos9YkHQS8XYR7U8NYVE0qKLVFWwsvyxMv6TnA=;
        b=P2W6WFdryogcRExcm9BHWy/LUYZlMjLiqcjC+D2Ee48ikyZbyY9st5PIRXgiQ1op/z
         ydr/jX5/RDivvtETYCoU0nGbG6Vv/lS9X8PstabtfPofRSmKUEj/S0EDU37XY3XMtAFA
         AcP141qLCkrxw+T9XbIUiB0whNS7JMiop6O1gjcR05TdiSwsrIeMF43JwrcybHI82+Wt
         nzhR5FeGhUalaJx32Rc0F7nrxJl0sxJ1VfsqRpvy5BK+FSvf1SHCaAdokfODptFEfEa4
         EihYsof+hsK6Ok0x++aYTuPkD86eh0f6YavH9rM9osJxqO+JbYyJGvRhR5dubWBnjxE3
         xghQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz5POOwwuqwg/1UNc2IOPDU0FMJeqeGzXCcr6Nl/UHTQJMwYcQz
	1VTqCXfVk/tD3vyONWkOeDE=
X-Google-Smtp-Source: AGHT+IGkTzmQo2A46eQEMKng1XbGUaMblrQZsXrA5rTcnxrvBTjM5oH811ko78FPw6HftthAK/NSEg==
X-Received: by 2002:a05:6a20:4425:b0:18b:cb93:ebd9 with SMTP id ce37-20020a056a20442500b0018bcb93ebd9mr10199264pzb.54.1701033257605;
        Sun, 26 Nov 2023 13:14:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1398:b0:6cb:4a9a:4f33 with SMTP id
 t24-20020a056a00139800b006cb4a9a4f33ls2052803pfg.0.-pod-prod-02-us; Sun, 26
 Nov 2023 13:14:16 -0800 (PST)
X-Received: by 2002:a05:6a00:2d81:b0:6c3:9efc:683c with SMTP id fb1-20020a056a002d8100b006c39efc683cmr2538649pfb.0.1701033256279;
        Sun, 26 Nov 2023 13:14:16 -0800 (PST)
Date: Sun, 26 Nov 2023 13:14:15 -0800 (PST)
From: Fenna Jaggers <jaggersfenna@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <1e7a73d4-f77a-4747-b9ae-bc5ba47d1b43n@googlegroups.com>
Subject: Voltron Papercraft.rar
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_19786_570222885.1701033255456"
X-Original-Sender: jaggersfenna@gmail.com
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

------=_Part_19786_570222885.1701033255456
Content-Type: multipart/alternative; 
	boundary="----=_Part_19787_625100708.1701033255456"

------=_Part_19787_625100708.1701033255456
Content-Type: text/plain; charset="UTF-8"

How to Make a Transformable Voltron PapercraftVoltron is a popular anime 
series that features a giant robot composed of five lion-shaped vehicles. 
The robot can transform into different modes and fight against evil forces. 
If you are a fan of Voltron, you might want to make your own papercraft 
model of it. In this article, I will show you how to make a transformable 
Voltron papercraft that can switch between the lion mode and the robot mode.

voltron papercraft.rar
DOWNLOAD https://t.co/4HeA4d73Om


What You NeedTo make this papercraft, you will need the following materials:
Paper (preferably cardstock or thick 
paper)PrinterScissorsGlueRulerPencilKnife or cutterWire or toothpicks 
(optional)What You DoTo make this papercraft, you will need to follow these 
steps:
Download the template for the Voltron papercraft from this link. The 
template was created by Nadask, a talented papercraft artist from Korea. 
You can also check out his blog here for more of his amazing works.Print 
out the template on paper. You can choose the size and quality of the print 
according to your preference. You can also adjust the color settings if you 
want.Cut out the parts of the template using scissors. Be careful not to 
cut off any tabs or fold lines. You can use a knife or cutter for more 
precise cutting.Fold the parts along the fold lines using a ruler and a 
pencil. Make sure to fold them in the right direction (mountain or valley) 
as indicated by the dashed lines.Glue the tabs to the corresponding edges 
to form the parts of the Voltron. You can use wire or toothpicks to 
reinforce some joints if you want. Follow the instructions and 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1e7a73d4-f77a-4747-b9ae-bc5ba47d1b43n%40googlegroups.com.

------=_Part_19787_625100708.1701033255456
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

How to Make a Transformable Voltron PapercraftVoltron is a popular anime se=
ries that features a giant robot composed of five lion-shaped vehicles. The=
 robot can transform into different modes and fight against evil forces. If=
 you are a fan of Voltron, you might want to make your own papercraft model=
 of it. In this article, I will show you how to make a transformable Voltro=
n papercraft that can switch between the lion mode and the robot mode.<div>=
<br /></div><div>voltron papercraft.rar</div><div>DOWNLOAD https://t.co/4He=
A4d73Om</div><div><br /></div><div><br /></div><div>What You NeedTo make th=
is papercraft, you will need the following materials:</div><div>Paper (pref=
erably cardstock or thick paper)PrinterScissorsGlueRulerPencilKnife or cutt=
erWire or toothpicks (optional)What You DoTo make this papercraft, you will=
 need to follow these steps:</div><div>Download the template for the Voltro=
n papercraft from this link. The template was created by Nadask, a talented=
 papercraft artist from Korea. You can also check out his blog here for mor=
e of his amazing works.Print out the template on paper. You can choose the =
size and quality of the print according to your preference. You can also ad=
just the color settings if you want.Cut out the parts of the template using=
 scissors. Be careful not to cut off any tabs or fold lines. You can use a =
knife or cutter for more precise cutting.Fold the parts along the fold line=
s using a ruler and a pencil. Make sure to fold them in the right direction=
 (mountain or valley) as indicated by the dashed lines.Glue the tabs to the=
 corresponding edges to form the parts of the Voltron. You can use wire or =
toothpicks to reinforce some joints if you want. Follow the instructions an=
d=C2=A0</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1e7a73d4-f77a-4747-b9ae-bc5ba47d1b43n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/1e7a73d4-f77a-4747-b9ae-bc5ba47d1b43n%40googlegroups.com</a>.<b=
r />

------=_Part_19787_625100708.1701033255456--

------=_Part_19786_570222885.1701033255456--
