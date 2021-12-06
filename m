Return-Path: <kasan-dev+bncBCJPVF5T2ADRBFMMW6GQMGQEFPXVGDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8811546913C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 09:13:09 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dsf5738518wmc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 00:13:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638778389; cv=pass;
        d=google.com; s=arc-20160816;
        b=BMeNeXXzEPdWdrt0m2lvLuoYSOmowZ/iDPklkyIhjvd0dnlA2ndDp6pTUoUP0Or+Zd
         J6p4I7QBPHVZjCV5qPoyHiPQjG8n4GubQVpQXlz29MPWq1N8sZA0yy95TXvfQ+igjhWF
         KP3F0s/wUZzUAGZSdamMEaAosUhRA5A6XnvF0mNvfVklB6sx03ViiH7UZjkBe3PjDLP8
         slxWZAFpnBaqY8YKX0YV2NxaigkAjSO48SsK0Oxo7VenOi5urCgmtjxgeOUKRfcjUn1D
         /AOnImFJDKHxcnWNOLkPBenlv1Vejld32Szm61/QXPn8RclOWMwQoAqQl1S1+fBixaVu
         IkIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=jnHMlUXYkEppmD3zc+iv5Wg9OFqIML6Tv395UEsy7Wg=;
        b=jjghlWm3eXV/7sfKEatdBb4zxK/OzP7gV0ua0SPHc5+g/w2f9cj3j6hmFrZoiiRhE1
         FjcOQc08GTzJIpy86Y8UAijlBgw9/cEu6zca3L9I3/k+z2XdHmMZU5WGsK6j+ylqPVW2
         TI9SsHn/2FUI0UnfjzS2m7ZX334pFn7pMFCRJ4n8PSNU2T8PH9H8rOdeeO3W54C7jizL
         o/bCkX/p/jtSmYVqdZdfxm0L395nOJnghxO1Uih3ITI3C1IW75H6alnZeRnVBFxD9Hud
         XJX/UH7f3iuAouTXTEMwHBJ/ht4yn7X9b0WCsyw0yKanIVYTEyd+LRjbJNrZY6rPm1OT
         x+Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ig7cZMSU;
       spf=pass (google.com: domain of adjallaherica@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=adjallaherica@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jnHMlUXYkEppmD3zc+iv5Wg9OFqIML6Tv395UEsy7Wg=;
        b=n8nX9pX3hvtARK33DLpuM/Ii7vp9lYlwfpgfzYw2vQWuU2UcfDJx48FlyDQV1kLDbm
         8lbSeF9UV1Tk0y8N3w/ib1BDthrcG3r5C85EsngaQRtYmqKjaM9D3/TdOD8wygFFFKaU
         J8ktD+1Jaiy4a5bP/ALLaz/POj2LhcrMatUSvQ3A4YWxt+0xQCAKXFQiDXtHpNhacpwr
         2cn2bEHm64D5BIjVs8czIaYj4ge5QnhY3WBHYdlsAKoRHs5F1mIvr/W3p4lfdyfTHrpF
         UBIhWaMM59VCztGRPuvjyOyyAePxov3ppQRFu1zpuA9lV7CJrqlL0/9ajxdsWvKCkul/
         B7Lg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jnHMlUXYkEppmD3zc+iv5Wg9OFqIML6Tv395UEsy7Wg=;
        b=BgpAMYKKnQuRP3Yzk/Fe0NN8/EYQCtWR2GS/k7fRs5l5Ic3M+Plxlvak6oW0sL9sUY
         x2+778PQLqMj+xYfQwKO4ohBlcbk1dINtb09MddiMgnF3sfwvusLyIzNowGKEvAA/alu
         5yN7IqFCZZ5X0tc59DIs3XrFhokvtorjeGr8RoD8niQ+0uAGmrdmzmIkRB41Wki1xOaJ
         O7GpzIo4FJ639bn1SWaDVI1xoiub/tvwEEtrr1m6gij4SzGLTVR0GLjQe3rgvPLYs80N
         wlk00IybZxe5yJbobCxYWE6quDoLRvUkWORu9g7kphsTELMui3zYK1J6OKm0zLOfUda+
         pT7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jnHMlUXYkEppmD3zc+iv5Wg9OFqIML6Tv395UEsy7Wg=;
        b=UmUauZpfBSqUJEBexg6/KDbVErPuFTonK3XArn5TEGKTjkZc/3XnL6ibCLT6OKbx68
         aXkwoN7lF+7iOJ7/o9inKcO36GyUai2cI3elt5HtKfmqGKSFCiplTt4Lb7Vkk+D20fak
         472me9vKzzqmBC2J6RRNbHNajZJfZL9U0muYKjAYffazNjMkL59/zTy80/QK5MfuEQ7n
         BWqPqCMIwPbYIR7nDV/XNW4aq/VtxXyQl/IFzmf9RiOuSQ8GQQpV3dcpF4XWGo7XzgXx
         OU3+F96C9+ICHgnZX//mrDcNEkamoYjlmJO5/rdPiwtx5i+B2I3KObDQilwSZDKMpj1+
         39WA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bl6ecvNtYo4CBkSCwBdKJgBY6SMV2lfxneozX72GrcAjw2FfV
	ZQQxN6IYmcxlfFYz7I6yOEw=
X-Google-Smtp-Source: ABdhPJw19MkFs7ClgMEshlS4ULg+B3llXnOpRVLtB0/04IXUZgYG5M8WS76F9EiMQNNEVdZxoa2XPg==
X-Received: by 2002:a05:600c:4113:: with SMTP id j19mr37878629wmi.48.1638778389311;
        Mon, 06 Dec 2021 00:13:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls1302545wro.2.gmail; Mon, 06 Dec
 2021 00:13:08 -0800 (PST)
X-Received: by 2002:a5d:508d:: with SMTP id a13mr42444117wrt.41.1638778388267;
        Mon, 06 Dec 2021 00:13:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638778388; cv=none;
        d=google.com; s=arc-20160816;
        b=a1aSC8mGIq5IDBUUSIozSHmUiBcWdNVynb1qUNECsvvImOF5d8x9Q2V8yXglE4HGyK
         dkVDsNyRJnR5h2E+HoQZEQKTbvGFmfXnS1UdWMaqyNPKGHupHeud5vXeVkBXzjDRG1aG
         KswLARN46PgYSWOITtorssWVdf7LQxCAty4qXd46Lf4ItvBEZACbPl6JzVqIGu1RPQro
         FI2sA9t+pa8EtNWnJV5IVl7jhDAPmDdeH5WR8AQ5R9AUmSGIml0m6ZQWeHVXjrqsUNr1
         DsHrxeb7EanyNEq2rqohUEKftDy4LqGElAPF8zH6YuaZLzIlxmS2CTV0IY45Gzwr781Y
         njBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=6VCz90fV7uATxr+uhNJlr6A9Yr4qXaw5oyXz09QmiiY=;
        b=XWtLrN8zbHCBZpam4De4W/dfbFic+V1YtMRQLnxtRe41PSE9fKVDJ1z+8YVELk8btS
         NKrquvs57pCbRBvXVVzkDmLcvO9Ai8uD202AlHr7pSsjnRKaxR1yy10D//jpu6r3pt9V
         20NqQ3QhF38qHrPTlEEk7jSZ2Ak+Erbzt/mPCIlZiZ15XHmAAU4ii2tCFYsp4QzMuKxO
         0BqN+D+Zb52n+w9lY9f1GGpYrjsTpsHtYtneDX43p6BWHcqD+Bq4Dzi0d3gSEHQx308S
         EKAqyyXsy4HjhC7XCRlWS/Elt5OKgOhGUTFN4ZoFjXbhd8NBFbqoplbxRAG+hAxaIMod
         NFWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ig7cZMSU;
       spf=pass (google.com: domain of adjallaherica@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=adjallaherica@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id r6si677943wrj.2.2021.12.06.00.13.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 00:13:08 -0800 (PST)
Received-SPF: pass (google.com: domain of adjallaherica@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id x15so39649252edv.1
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 00:13:08 -0800 (PST)
X-Received: by 2002:a50:e683:: with SMTP id z3mr53064875edm.206.1638778387998;
 Mon, 06 Dec 2021 00:13:07 -0800 (PST)
MIME-Version: 1.0
From: Ulrika Jeca Meir <ms.meirjessic@gmail.com>
Date: Mon, 6 Dec 2021 08:12:48 +0000
Message-ID: <CABkd9YzGs+tOBMbnAjQJO+2W1CXVogVRPbtWTRgWGBaGXMbPFA@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000aead6405d275d362"
X-Original-Sender: ms.meirjessic@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ig7cZMSU;       spf=pass
 (google.com: domain of adjallaherica@gmail.com designates 2a00:1450:4864:20::52a
 as permitted sender) smtp.mailfrom=adjallaherica@gmail.com;       dmarc=pass
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

--000000000000aead6405d275d362
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

KuC4quC4p+C4seC4quC4lOC4teC4leC4reC4meC4muC5iOC4suC4oi8gR29vZCBhZnRlcm5vb24q
DQoNCirguIHguKPguLjguJPguLIqICrguITguLjguJPguYTguJTguYnguKPguLHguJrguILguYng
uK3guITguKfguLLguKHguYHguKPguIHguJfguLXguYjguInguLHguJnguKrguYjguIfguJbguLbg
uIfguITguLjguJPguKvguKPguLfguK3guYTguKHguYgqKj8gL3lvdSBzcGVhayBFbmdsaXNoPyoN
Cg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmli
ZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJl
IGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQg
YW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZp
ZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xl
LmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQUJrZDlZekdzJTJCdE9CTWJuQWpRSk8lMkIyVzFDWFZv
Z1ZSUGJ0V1RSZ1dHQmFHWE1iUEZBJTQwbWFpbC5nbWFpbC5jb20uCg==
--000000000000aead6405d275d362
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><p class=3D"MsoNormal" style=3D"margin:0in 0in 10pt;line-h=
eight:115%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><s=
pan style=3D"font-size:12pt;line-height:115%;font-family:&quot;Cordia New&q=
uot;,&quot;sans-serif&quot;;color:rgb(0,176,80)">=E0=B8=AA=E0=B8=A7=E0=B8=
=B1=E0=B8=AA=E0=B8=94=E0=B8=B5=E0=B8=95=E0=B8=AD=E0=B8=99=E0=B8=9A=E0=B9=88=
=E0=B8=B2=E0=B8=A2/ Good afternoon</span></b><b><span style=3D"font-size:12=
pt;line-height:115%;color:rgb(0,176,80)"></span></b></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 10pt;line-height:115%;font-s=
ize:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span style=3D"font=
-size:12pt;line-height:115%;font-family:&quot;Cordia New&quot;,&quot;sans-s=
erif&quot;;color:rgb(0,176,80)">=E0=B8=81=E0=B8=A3=E0=B8=B8=E0=B8=93=E0=B8=
=B2</span></b><b><span style=3D"font-size:12pt;line-height:115%;color:rgb(0=
,176,80)"> </span></b><b><span style=3D"font-size:12pt;line-height:115%;fon=
t-family:&quot;Cordia New&quot;,&quot;sans-serif&quot;;color:rgb(0,176,80)"=
>=E0=B8=84=E0=B8=B8=E0=B8=93=E0=B9=84=E0=B8=94=E0=B9=89=E0=B8=A3=E0=B8=B1=
=E0=B8=9A=E0=B8=82=E0=B9=89=E0=B8=AD=E0=B8=84=E0=B8=A7=E0=B8=B2=E0=B8=A1=E0=
=B9=81=E0=B8=A3=E0=B8=81=E0=B8=97=E0=B8=B5=E0=B9=88=E0=B8=89=E0=B8=B1=E0=B8=
=99=E0=B8=AA=E0=B9=88=E0=B8=87=E0=B8=96=E0=B8=B6=E0=B8=87=E0=B8=84=E0=B8=B8=
=E0=B8=93=E0=B8=AB=E0=B8=A3=E0=B8=B7=E0=B8=AD=E0=B9=84=E0=B8=A1=E0=B9=88</s=
pan></b><b><span style=3D"font-size:12pt;line-height:115%;color:rgb(0,176,8=
0)">? /you speak English?</span></b></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CABkd9YzGs%2BtOBMbnAjQJO%2B2W1CXVogVRPbtWTRgWGBaGXMbPF=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CABkd9YzGs%2BtOBMbnAjQJO%2B2W1CXVogVRPbtWTRgWGB=
aGXMbPFA%40mail.gmail.com</a>.<br />

--000000000000aead6405d275d362--
