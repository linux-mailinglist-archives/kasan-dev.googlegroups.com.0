Return-Path: <kasan-dev+bncBAABB6HCXXTQKGQEGTN454I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-it1-x13f.google.com (mail-it1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54D5D2F756
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2019 08:00:26 +0200 (CEST)
Received: by mail-it1-x13f.google.com with SMTP id p19sf4174432itp.6
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 23:00:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559196025; cv=pass;
        d=google.com; s=arc-20160816;
        b=wYtw41wfRqmxqw27reIgGSSrW4BOKmkYdptTzYBUa9EljIi+CEBF8kE86s6hxG2dCW
         WZRQjqQ2J5xDXCqp/JTxbiL4LpVUmbbmhSkxT87mxzZMs1IANAKi3K713wrdmLTxP/vx
         Bs/M/yLq5QjnQUQIfj9xiQmopRayp+Hh48GS7hgQUjbKtKY4vlEWtUNgAWjDxp/W85Nj
         02UNe54AnETSsc/50AkpTUmAh4bjpEIAVkr0l5GN756UGPykuZGWjq5SUOWq2FNyH+JJ
         Og0PT7fx75QAPHC8z45IYYg5jz2GhiAnlG38NwNXvxS2eUhFPTmojomGlc4l1pnbyXVB
         yMYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:mime-version:subject:to
         :from:date:sender:dkim-signature;
        bh=Zm2uzJv/ifnneBi1E8z6l3HPxVMwOmDC3px/6xcNZSo=;
        b=RnLsY1Mna+HOXPNwwqeHiYeEL9BACccM+gAOMrKYHprIYMrk+G5cmQrLN6HYa581+s
         ul9WCR5783YQtNgUabwaVcvvOPGF250vU2tRPm5AhlfWq10HoNnoTQ+dylfKOlE3u0nc
         QBLKY/CrD3BKzsUYVhexH0uD6wgbyjFa/l/oWs4klxMIOr5VaWw6Qix0649BPdMJ3qf3
         r94Zfljb62uI60fj5Soip4Qs1OgwZr1v0O9wbGZi36z+gEVcKRfAQhYlNS9uS3sBJXKG
         3ygw4ESygzAXxMhLjcbFKzV49Nim/29RS6Nt1+/VM3HnoYmlgcLA1T8ltZ3y8iLPgo6+
         Ctbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=OqfwmqMO;
       spf=pass (google.com: domain of gjs_vb2@163.com designates 220.181.13.79 as permitted sender) smtp.mailfrom=gjs_vb2@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:subject:mime-version:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zm2uzJv/ifnneBi1E8z6l3HPxVMwOmDC3px/6xcNZSo=;
        b=ZJVo5xJwP7bvK0XesqVl3fsA9FuXQ1Y7+XxalfJ2Y9SU2ylw4W58hTen1hW2vZg5bc
         UhRb1at6VrlSRFtLelZ27RIhXceO9v3CSlSiKf67gJotOkKRNQqU12Q8FFiX26l+q4yc
         iH3pfYdSUWYG/CrL1VJITqj4aypeu33tgaaipp2YKdtrAa2/VSQ8TkoMc8dTH5Svd2t+
         +lI/RsrSwqCeL0ZJICjS4mLbSGVcSVpkNeRT+cHbMuhWkZrAN2X2zYjdzY+VzP0U6POi
         3kpfwwMgSbKy2Hkn9zTzBUBbVF1KVoLEcyVTGVPkdiOFvENwzv1aVWIj3kMZ8LUNwMNT
         S+nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:subject:mime-version
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zm2uzJv/ifnneBi1E8z6l3HPxVMwOmDC3px/6xcNZSo=;
        b=t+K00PhJTRPx3izAgrvr2Tos3x9ijsabiHvF7gg59FD35TC6199U1VoIM1BUQKsTkv
         vQFB0uyrd6xHHA23+qFn+pbu2sDTr8LwLMCsjE6YAMXHZ+1nX7/Ptm2t1fJDDfi8dzYI
         iw//AOZh7m5B+JwNLSAzdEPGCz7n8/bq50tTKRCbyUT+qGvNJIQd7KwdJkp/n/1w7pi4
         kXCBDZiq+cTKa7VGnGiSjtnZfPxkWbVl6wigXPX2lWl4PduYUKQ+7EEsoCVv0g/tLYJc
         9LztkgEzr+PweArbAt5cxQCzQzjsEogmy7O36gviKl8gDOON/X6R1dmISaVzx7jqifsw
         XAHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUdwRBaG6tELinNqpWiEy/39g2623ooN0UPbPaPeBFKhtdOPfQZ
	yRmfAjFpDCK8x5DkuOxsnPI=
X-Google-Smtp-Source: APXvYqxwaTZE1jekSR5o3hERVhVz/0tYEXnGG63UerxOOl8umiJCV62QpQLV9SV2yf0RUxNpHQ09Wg==
X-Received: by 2002:a6b:bc02:: with SMTP id m2mr1569670iof.25.1559196025051;
        Wed, 29 May 2019 23:00:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2b7:: with SMTP id d23ls392686jaq.16.gmail; Wed, 29
 May 2019 23:00:24 -0700 (PDT)
X-Received: by 2002:a02:ccb8:: with SMTP id t24mr1092771jap.59.1559196024809;
        Wed, 29 May 2019 23:00:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559196024; cv=none;
        d=google.com; s=arc-20160816;
        b=ltutqRvDQ+CdW+PhVOx2zSve3rUebg1Z7AOhq9QPxT9MyBxE/iLT+AwYgAv0b3W0Uq
         DZOCFkzBY+P8l369jaIY8gumyPeLAdXw77/Iqb8XV2es4wrT79c/lJq4bwuWIf334nF2
         j2dCbDd80dgbzMNas25pug5lbxBYrpVp+2sX/5BJsDMpZMr8gehyM2a8/73i4I72BSDJ
         HmHOtrSlVOhxcBBRKDnTrnSwsp3rkOW4v+9Y9Izft+Hg3nPvGGJE2986iAaNjGkyvuWo
         DJ5a2RlvKkFT5k9PAoY0/gxp4qx7hudOYvLRJBd+JsGPJUjlXBjFvbR5VNAYuqyICy29
         Z3UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:mime-version:subject:to:from:date:dkim-signature;
        bh=mWkdTOn7RjCvrhmNC6snmrXlzwlidci3AMmwF9Wl0YA=;
        b=cksZoM9t/NjkjfpC2sbwhv//oZBNNRmVReHz0xoS4JXR9oREJODvz5eCKmXJj9ZV5/
         +EUUw6FCSvFURYFC8D7m2HHJqcbzNoX1rcLzyr6+AkVJQdIYPKUl9hvl0G+vzXbF2tNa
         9uJAb1kddzPy7GXvODSleBBB7AkhTHvllSpPLiqWdEeKUwO+63oSOFr5QkWKjGUsnZAr
         0CpcSauUX0jU5R+mExMRFRgo1ylVHwdA+P+E8KHQ4/q9hNdp8BhiPcJq0QIdmJMO3bMu
         fRv2IMPavP1fbIs06u/I/bqqb23JyFWi6rtmX0F0cMjdwjMrB/mD70awMKnF/5YR8PAE
         6vtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=OqfwmqMO;
       spf=pass (google.com: domain of gjs_vb2@163.com designates 220.181.13.79 as permitted sender) smtp.mailfrom=gjs_vb2@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m13-79.163.com (m13-79.163.com. [220.181.13.79])
        by gmr-mx.google.com with ESMTP id y3si71628ioy.2.2019.05.29.23.00.24
        for <kasan-dev@googlegroups.com>;
        Wed, 29 May 2019 23:00:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of gjs_vb2@163.com designates 220.181.13.79 as permitted sender) client-ip=220.181.13.79;
Received: from gjs_vb2$163.com ( [120.230.93.150] ) by ajax-webmail-wmsvr79
 (Coremail) ; Thu, 30 May 2019 13:59:14 +0800 (CST)
X-Originating-IP: [120.230.93.150]
Date: Thu, 30 May 2019 13:59:14 +0800 (CST)
From: Brant <gjs_vb2@163.com>
To: kasan-dev@googlegroups.com
Subject: =?GBK?B?xOO7ucrWuaTU2kdPT0dMRcnPy9HL97/Nu6ejvw==?=
X-Priority: 3
X-Mailer: Coremail Webmail Server Version SP_ntes V3.5 build
 20180927(cd7136b6) Copyright (c) 2002-2019 www.mailtech.cn 163com
X-CM-CTRLDATA: RM8rPWZvb3Rlcl9odG09Njc1OjU2
Content-Type: multipart/alternative; 
	boundary="----=_Part_147650_544665910.1559195954677"
MIME-Version: 1.0
Message-ID: <64b945c0.950a.16b07522df5.Coremail.gjs_vb2@163.com>
X-Coremail-Locale: zh_CN
X-CM-TRANSID: T8GowACHZ6oyce9cFch3AA--.65296W
X-CM-SenderInfo: pjmvs4jes6il2tof0z/1tbiJQvE4FUMRsVVcgAAs3
X-Coremail-Antispam: 1U5529EdanIXcx71UUUUU7vcSsGvfC2KfnxnUU==
X-Original-Sender: gjs_vb2@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=OqfwmqMO;       spf=pass
 (google.com: domain of gjs_vb2@163.com designates 220.181.13.79 as permitted
 sender) smtp.mailfrom=gjs_vb2@163.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=163.com
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

------=_Part_147650_544665910.1559195954677
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOi0uOWwj+S4gy0tICAg5Li75Yqo
5byP6JCl6ZSA57O757ufCgox77yJ5pON5L2c566A5Y2V77ya5pmu6YCa5Lia5Yqh5ZGY57uP6L+H
566A5Y2V5Z+56K6t5Y2z5Y+v5LiK5omL5pON5L2c44CCCgoy77yJ5aSa57u05bqm6YKu566x5oyW
5o6Y77ya6YCa6L+H5aSa56eN5pa55byP5rex5YWl5oyW5o6Y55uu5qCHIOWuouaIt+iBlOezu+mC
rueuseOAggoKM++8iUFJ5rex572R6K+G5Yir77yaIOiHquWKqOivhuWIq+mCrueuseiBjOS9je+8
jOW4ruaCqOaJvuWIsOiAgeadv+OAgemHh+i0remCrueuseOAggoKNO+8ieaZuuiDveWuouaIt+aO
qOiNkO+8muagueaNrueUqOaIt+WFs+azqOWuouaIt+iHquWKqOaOqOiNkOWFqOeQg+ebuOS8vOWu
ouaIt++8jAogICAgICDnlKjmiLflj6rpnIDopoHngrnlh7vlhbPms6jljbPlj6/ml6DpmZDojrfl
vpfmlrDlrqLmiLfjgIIKCgoxMjYwODE4ODE5LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVEN
Cg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmli
ZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJl
IGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQg
YW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHBv
c3QgdG8gdGhpcyBncm91cCwgc2VuZCBlbWFpbCB0byBrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNv
bS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gb24gdGhlIHdlYiB2aXNpdCBodHRwczovL2dyb3Vw
cy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzY0Yjk0NWMwLjk1MGEuMTZiMDc1MjJkZjUu
Q29yZW1haWwuZ2pzX3ZiMiU0MDE2My5jb20uCkZvciBtb3JlIG9wdGlvbnMsIHZpc2l0IGh0dHBz
Oi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9vcHRvdXQuCg==
------=_Part_147650_544665910.1559195954677
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBzdHlsZT0ibGluZS1oZWlnaHQ6MS43O2NvbG9yOiMwMDAwMDA7Zm9udC1zaXplOjE0cHg7
Zm9udC1mYW1pbHk6QXJpYWwiPjxkaXY+PHNwYW4gc3R5bGU9ImZvbnQtc2l6ZTogMThweCI+PHN0
cm9uZz4mbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJz
cDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsm
bmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJz
cDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDsmbmJzcDvo
tLjlsI/kuIMtLSZuYnNwOyZuYnNwOyDkuLvliqjlvI/okKXplIDns7vnu588YnI+Cjxicj4KMe+8
ieaTjeS9nOeugOWNle+8muaZrumAmuS4muWKoeWRmOe7j+i/h+eugOWNleWfueiureWNs+WPr+S4
iuaJi+aTjeS9nOOAgjxicj4KPGJyPgoy77yJ5aSa57u05bqm6YKu566x5oyW5o6Y77ya6YCa6L+H
5aSa56eN5pa55byP5rex5YWl5oyW5o6Y55uu5qCHIOWuouaIt+iBlOezu+mCrueuseOAgjxicj4K
PGJyPgoz77yJQUnmt7HnvZHor4bliKvvvJog6Ieq5Yqo6K+G5Yir6YKu566x6IGM5L2N77yM5biu
5oKo5om+5Yiw6ICB5p2/44CB6YeH6LSt6YKu566x44CCPC9zdHJvbmc+PGJyPgo8YnI+CjxzdHJv
bmc+NO+8ieaZuuiDveWuouaIt+aOqOiNkO+8muagueaNrueUqOaIt+WFs+azqOWuouaIt+iHquWK
qOaOqOiNkOWFqOeQg+ebuOS8vOWuouaIt++8jDxicj4KJm5ic3A7Jm5ic3A7Jm5ic3A7Jm5ic3A7
Jm5ic3A7IOeUqOaIt+WPqumcgOimgeeCueWHu+WFs+azqOWNs+WPr+aXoOmZkOiOt+W+l+aWsOWu
ouaIt+OAgjxicj4KPGJyPgo8YnI+CjEyNjA4MTg4MTktLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tUTwvc3Ryb25nPjwvc3Bhbj48L2Rpdj4KPC9kaXY+PGJyPjxicj48c3BhbiB0aXRsZT0ibmV0
ZWFzZWZvb3RlciI+PHA+Jm5ic3A7PC9wPjwvc3Bhbj4NCg0KPHA+PC9wPgoKLS0gPGJyIC8+Cllv
dSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhl
IEdvb2dsZSBHcm91cHMgJnF1b3Q7a2FzYW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpUbyB1bnN1
YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0
LCBzZW5kIGFuIGVtYWlsIHRvIDxhIGhyZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJzY3JpYmVA
Z29vZ2xlZ3JvdXBzLmNvbSI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb208
L2E+LjxiciAvPgpUbyBwb3N0IHRvIHRoaXMgZ3JvdXAsIHNlbmQgZW1haWwgdG8gPGEgaHJlZj0i
bWFpbHRvOmthc2FuLWRldkBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXZAZ29vZ2xlZ3JvdXBz
LmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQg
PGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi82NGI5
NDVjMC45NTBhLjE2YjA3NTIyZGY1LkNvcmVtYWlsLmdqc192YjIlNDAxNjMuY29tP3V0bV9tZWRp
dW09ZW1haWwmdXRtX3NvdXJjZT1mb290ZXIiPmh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9t
c2dpZC9rYXNhbi1kZXYvNjRiOTQ1YzAuOTUwYS4xNmIwNzUyMmRmNS5Db3JlbWFpbC5nanNfdmIy
JTQwMTYzLmNvbTwvYT4uPGJyIC8+CkZvciBtb3JlIG9wdGlvbnMsIHZpc2l0IDxhIGhyZWY9Imh0
dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9vcHRvdXQiPmh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5j
b20vZC9vcHRvdXQ8L2E+LjxiciAvPgo=
------=_Part_147650_544665910.1559195954677--

