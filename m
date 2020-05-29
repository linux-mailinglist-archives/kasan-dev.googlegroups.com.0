Return-Path: <kasan-dev+bncBCFLDU5RYAIRBNWZYT3AKGQEKCPKTWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id E38D41E8201
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 17:39:34 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id p10sf1192437wrn.19
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 08:39:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590766774; cv=pass;
        d=google.com; s=arc-20160816;
        b=tlEZct2zNBTW1U13wX/MAtowqSccw8+26Wq8W8/QL3JOtDtPeIHNG8TSFyqekCxMCa
         lg7F0u0VFuj8jeYlLmvy0szjtoShQJI6pzWHQOBtjcoTFVoROikPBBDwif2fhJey6+kP
         zfHkeEMpOOs8zmRZOA0PHLDrjJfFVYBzsLkTferyw0ACcqnCpElJx31CGMuF3psnjZzy
         3qlFAsx/mUvanY8pdCm8rCI3Su0NildrinRjUm9KYOQWwgh3ptfJ+HmMWaIJ4QKxbmXE
         aC0XMVMbN3LFktPn4s/lp697YkinwOuRrDbaSe4nzZqMLdLnFjENa93XvjHpzm86U/tr
         jY4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=+Sccr8BjK5YWyQMMT3up2Nk1QeaqkUdpTxggWjOVzK0=;
        b=vtnrzBBHHnIuwSIVsNQIHd4qSrl2x7QUqbZqiC4IJ/wB/9nAwXAdqTnoJK3QP0Ay9/
         Vh+wdGNNPBIvASxpIkoESLijuon10iREfTqJEoyCww67a250nvtDKOuy+T3s/6gZXYyv
         8mp8bPgXKngOXjUjqBmITYATS6x+H6xQjc5tk+OTTj6pWKoYxB1SbKbEYbsz2jCOA4MM
         gmuq8x2ZRIHDyg8FBZsxwS5Nc7Q+8yICMgvZLf49xIqSroq4ldIXffREYbV2FUGkuDsP
         3ZQEjUo2wR1uIk35UVnHI+x3kH0e+5Te3853bfbtPUIisK23tK63joUBlKL1rwO9q/Z5
         H++w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lFM0WuGb;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Sccr8BjK5YWyQMMT3up2Nk1QeaqkUdpTxggWjOVzK0=;
        b=Yx/TS/KaQD926OenLhOo7eoR6oMCRoIEJ80Yak2BYW1+IIuvIiknjtQf78J4k3iQ6B
         iWZPV42oMmGnqQ8HeYJNbe3WUdJ6IAFhmWqgH/TAOKgCyfHlgfwyTkIaG+2dzmXSh63z
         xMM6s5EQrSasqzgx6a13S4SEbvomAZVbNtdDVD/wUT6Rny6iD7fUvczg4TppySTVobsl
         mMBRvHKr5twlO9lpe1oM71szoyqJAOHpUP8XqkHSYFY6OWDeW3JpsS6tPLXvXQbefdAJ
         V2VmxGBx/jbEQe/jNnTbpXwF/sHBV60ecIIjQKQnSOrZ6VQdmjJNwjNjEjbPwsBQnk82
         ejCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+Sccr8BjK5YWyQMMT3up2Nk1QeaqkUdpTxggWjOVzK0=;
        b=PEDCA1nR1j7FHNNxKpj2P3bNLXff5/j9O5eewl1uYOy1m72II2357mQLEqBpUnAzpQ
         y1pEmLQLLtb4g8ALGbF0RmMW8ZP9mHj19WxdyW8L/L0EcAgkU2Xo+qrdC3Ce9auJz3Z1
         hE9GlBVq4sxXdlnt85XAbL9JO0+wyblvk3AgK5Tt32li0tr5+IjyU2K34HIjDK1MQqkS
         lWCT6IGQxXDkDILDl/fQsNbswdBD7vrwrXKP1B/mIbesjIiGEgO7XMUtpYJPNWb4uBOp
         6LBhr/WPaBOGjoyWc+G+mABUayUZpRSNvfbuZYYfrv6jYUTlK988l6nxuYBkdIp1MsBa
         GiBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+Sccr8BjK5YWyQMMT3up2Nk1QeaqkUdpTxggWjOVzK0=;
        b=VhrpXk/00mHP4Jv1yxt88RZFmLQNkm5uxZsMjI+y30W34gXIeaAECu/gel/OOrWh1c
         zIwBVdzSDxZGSLBfIRAGc0/adkVOZdqrTV7b/DkCoM9F5quOY/jSoWDY9fnL/OTmBk2z
         emPW67T9iHCvaBpbZ0vIZy/lw5xW+2skklQW/aG4giG7skaWM9Qm7VPAwnMeytt9bjn6
         GXCe/ZD2Ae0Ydw29sRvTs7tVFCQsvXlVuzPvKjgqTEeG41tVuVxtrUFr/oWwH2a9yzCI
         KhCXnoke7nyEKzSZQbtigUK+FQqnkIc3TG4IdFlJvjqPMcgQsuQpnkuljAzE5oqwws9y
         sXYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gSNBAtisH/g2UOuLKhNsKnpAzKXdGFmYn3rhHHI3XzCGKuew/
	ogRgbXah4mghuR9nwkyGyNM=
X-Google-Smtp-Source: ABdhPJwkmAR1R0ABoHNWBFjnhZn5YqkcEWk0mW+ppfSBIF27R8mcYgjxEkOvvZlJZo/aEnwRjK2sMg==
X-Received: by 2002:adf:a350:: with SMTP id d16mr9532265wrb.237.1590766774639;
        Fri, 29 May 2020 08:39:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5224:: with SMTP id i4ls7938775wra.0.gmail; Fri, 29 May
 2020 08:39:34 -0700 (PDT)
X-Received: by 2002:adf:9e03:: with SMTP id u3mr4334043wre.413.1590766774088;
        Fri, 29 May 2020 08:39:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590766774; cv=none;
        d=google.com; s=arc-20160816;
        b=DNAk8mGbCELEi3wTxHep3ADxlBZ8LWS6kKPMq3KlJL2jc/uav3WSSTuG2Np/r/5WOQ
         A1kWUJfXT875bNsZx+MxAHUZ1cHld4LJ4hpzmWp6JQrFKk6sY1IJ6DC8GYX08cKGe4WW
         +oNTEGFwqUy0z8J5S2oHxEBUKvadOkRxTxcHyl8LmrquUGIj+CwyTSOffHu3JxamXMks
         C447fkqGlvgPiNHw2f9gk2abvV3kVDQzZxrpU40MacaDgGnZBuRhj8Iu45778Y35aIxd
         8nX2XYdPYBGBHulp1t+LohQJAiYn2q3JgMVptCjaYG2MxhVu2FJUy7EOVkLBmnqgayg1
         NLAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=SftUeYQH7mtT/GvPJYIhfJPX+T4OKATA8tk7ILfB2+Y=;
        b=VGouyG5Ne0uOVTPYrv8gVUqb3FziB6hQtwVXIKaPzRDGU8S/m08IRKPm76DO/3hqEF
         hGftGXSc3IMjiFchpD0VL41adZQi46e5hp6CUstC1mzGl5f/G1QDvZkZqF0/SlsssnhH
         0mh6MPFwKz5x8yMxW+M+IbbnHzMuvA9fq7VrEK6vnhnBU/SbfHvgrwpkdG1YK1dqL/Nc
         Q3JGNLLPtYHD4QT+zJ83c3NoYmbHUkhQLrU/Nla34qCzy1pRP8ckWSI/JiwoDhFsQiMs
         CoChC4HQCrugBtbDQLImcu7Oq6b/TUE+iwuKTVL2YDxEIKPMdCS+2hYhXFapVtPNJR7p
         ts2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lFM0WuGb;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id f1si487826wrp.4.2020.05.29.08.39.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 08:39:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id o9so3140639ljj.6
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 08:39:34 -0700 (PDT)
X-Received: by 2002:a2e:97c3:: with SMTP id m3mr4123165ljj.23.1590766773141;
 Fri, 29 May 2020 08:39:33 -0700 (PDT)
MIME-Version: 1.0
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Fri, 29 May 2020 08:39:22 -0700
Message-ID: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
Subject: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="0000000000006f060605a6cb400e"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lFM0WuGb;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
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

--0000000000006f060605a6cb400e
Content-Type: text/plain; charset="UTF-8"

Hello All,

I started   porting
https://github.com/torvalds/linux/compare/master...ffainelli:kasan-v7?expand=1


to one out target , compilation seems fine but  target is not booting ,

Any help can be greatly appreciated

Thanks,
Venkat Sana

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkamtaXi8yr%3DkhO%2BE9SKe9QBR-Z0e0kdH4DzhQdzo8o-%2BEg%40mail.gmail.com.

--0000000000006f060605a6cb400e
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello All,<div><br></div><div>I started=C2=A0 =C2=A0portin=
g=C2=A0<a href=3D"https://github.com/torvalds/linux/compare/master...ffaine=
lli:kasan-v7?expand=3D1">https://github.com/torvalds/linux/compare/master..=
.ffainelli:kasan-v7?expand=3D1</a>=C2=A0</div><div><br></div><div>to one ou=
t target , compilation seems fine but=C2=A0 target is not booting ,</div><d=
iv><br></div><div>Any help can be greatly appreciated=C2=A0</div><div><br><=
/div><div>Thanks,</div><div>Venkat Sana</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkamtaXi8yr%3DkhO%2BE9SKe9QBR-Z0e0kdH4DzhQdzo8o-=
%2BEg%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CA%2BdZkamtaXi8yr%3DkhO%2BE9SKe9QBR-Z0e0kdH=
4DzhQdzo8o-%2BEg%40mail.gmail.com</a>.<br />

--0000000000006f060605a6cb400e--
