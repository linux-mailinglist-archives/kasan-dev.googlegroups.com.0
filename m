Return-Path: <kasan-dev+bncBDD2VNNPRMKBBJXW23VQKGQEJ75HTTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 949FAAD203
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2019 04:38:30 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z39sf7222901edc.15
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2019 19:38:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567996710; cv=pass;
        d=google.com; s=arc-20160816;
        b=u5MsKmVlsvWrApvi0IM8A2DZtonpg2kwhywnau6OdsWTjgQWrugA+Z0M9YefWVEGo+
         AxagvSTxL4SANC5ehHUH/0rOC+C/VFfWj/0YZZYVSEyH/zmMuZdxLxtAcYN7HnF1pcDI
         ErUrT98oTs7y5NtnjrZwMEjOK+DEhEzNnXNbx/A+Ult8rlaangi1wZgtVgeHTo21dkqZ
         AP9Ph/KYTlzK1kjCNcryf7GF1v1YzBntDS49XOUHh19sWeXgfklKS5cKVzPaQM5QzOOC
         v/POevHxMXH2foetFlq3JWT/VXKZXe1tJrreCuVGebqI5Ak0tVQpL2M7L8nI6QBaO0Xq
         EtHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:reply-to:date
         :mime-version:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=/qJqQNDK4zlT6h6M8S0Yb6x/ayLSlNBhUrXKw21BfIY=;
        b=CgnRQ1VqKe+H3eCiN7wBYWOWzlkMQbSqCM1npCB2tr3Pi/Wn9TXrNDT/f/itqZvc2q
         gg61XxBFZ0jXzF/SGHOfIwdg7d8Ha1FIY3BZwg/V+ZYznfwU/WGidvV53btkCquCCZbv
         qb/JdrqI54qUGOOJtuTgTk72V9e4WmG6JJWrEbGfs6GC/4+QW8hegMEmGUuFHbLuzEz3
         YpCN8focOQOCgde1EmLUT4gRpAYXJs/5WrgrXEdraH+zGDXzzypvYek6sSZDfDQ8r7/+
         uPBL2x4Zqq8snXhjEsyhFrJ6cRolvBKwXj68fau4XRtkQK0c841Yb/I86ErzZRfKrzOz
         M8NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bZiP4Vqd;
       spf=pass (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=nahwanngaycra@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:mime-version:date:reply-to:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/qJqQNDK4zlT6h6M8S0Yb6x/ayLSlNBhUrXKw21BfIY=;
        b=Kqbo/QgeVkA9zGvx8mvihV95UUi7qhmdasd0s7v6nq87Y4000I9gTvNjeH8zhGbgoT
         MvMAlOqyFu1IjbmfnuZlbIn2Q7buKJNg3LnGMgSkb6yoS55xj6MO3IMA+mHaJSDi+v55
         NdGVNBVZdw9iGcT8wdrxzwCDIAt7E/UsWsfn3FMo5Gh1jPcqzYfDhO2DtJjrvetgWQQj
         HkQSR0E0ycHDtL21vC9Rvd8XrIVI9JYj14g6gmXGkm6Q4JUaR3c/izEkJ5mvPo1oAl/A
         ajAgQayo4XaEdUja1IFab19YVg90y+/Ddhmq9Gc17eqaVGaCNensOtXOZpopS4pqdZj+
         Jz0A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:mime-version:date:reply-to:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/qJqQNDK4zlT6h6M8S0Yb6x/ayLSlNBhUrXKw21BfIY=;
        b=rL/KpsWS9TZW4UOt3uivOHj1i8CaKdBQiro6Rhv51U/Yevw3opTV219pi+4y+Ks2WW
         j9bEH3o9TYsStbxfdM+0qyHE0qVMDNyOMU5y1Rz81qFnwFZ1BCrWCbImlX7sk+ND+ROI
         YxTbQtlcimpZFZwKMaBExu6uhYKhKl+LZtSaS5gMCUQB6nrCC8yQyz3WfiUcX//VU5Mh
         07/qDIBq0WrVwSyp7RnVLCyzpudZm1A/qq3GnJWbJ6LlwFhlljIgr5emRcQOdadhvcaa
         5Aen2MHfeLNIN2RaQONywbtPqKcbj+g2Hvl4FbjgP9lGdeIELb95se1L3gif8nvsQPZt
         f1rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:mime-version:date:reply-to
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/qJqQNDK4zlT6h6M8S0Yb6x/ayLSlNBhUrXKw21BfIY=;
        b=F+k1qcpuT/BBekY9IIYdLO7d/o0nVPV3zrk7H14VFizcvwO9ggIf8zGMZ99LXBH25o
         IfLW9sBYXP/jPYn0+TtdBmDS25DdpHfoGAmQR228w7ZAQPvVmTkCfsSlJZl1AIHa4se8
         botV6K6jr7c+7j3M29tX3+gbfW7gDy56xTBStm7rL8JEA75viR7EpNlqXYyIHnqxubWA
         hcfZSLP/QGGK8oxhwFzFitWyxH3CTg+LTMd253nbq1u3aLu+3rWlkK0nH9rI6sRGT/13
         bmYxpnS03PpNJlUh5o9L1tVDrKWOfSJIZQ+gJs6utMWJ7pAgEVnvXkV7znJ+Yp6tjPLD
         hxUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVi3rLm7oBe/+FToO7KEcF2jQSeO6kdKZwAsXW+Nq1m1LHPNcs9
	by79MFrpwmP+D37R8hMoGEQ=
X-Google-Smtp-Source: APXvYqyit7NTVKeKJsl5+Ds3SvwcFaPJrkyCSjgV/N+2EaGld49k5nwfjJNB6Xofu+dWdZ/pCNDYVA==
X-Received: by 2002:a17:906:1312:: with SMTP id w18mr16929795ejb.149.1567996710330;
        Sun, 08 Sep 2019 19:38:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:f413:: with SMTP id r19ls3134768edm.2.gmail; Sun, 08 Sep
 2019 19:38:29 -0700 (PDT)
X-Received: by 2002:a50:ec0e:: with SMTP id g14mr16226355edr.28.1567996709972;
        Sun, 08 Sep 2019 19:38:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567996709; cv=none;
        d=google.com; s=arc-20160816;
        b=cBHSdXtFnpkaQzmRFv7uVkBsMzXNWuIi9IidhB3xkyNdQ1DiAjvInZXs46bfl0wtxC
         PFWPfETTPOvW6I+sssvsB29JXI/le9lFO/Blx7EGo7mhIJCSuNDab6DQ+qp/olsKgTJl
         6PTnpVI9EdKAB9qusc8F3EyhmEPaESw8tUpSFxCZiMMLSsgNCjkldY3FiVZhliA49ZfA
         Mc6tSkVyUG+6Evj5SHMLCzp2s2vt5yCH34TkygO8jewUZHawK/CwVMAQiP9Yiy2EGle4
         ihYdRe+nNHlWKe7N8Zd9B96eSVqKK8sqdEqvWpXGyPvGCdGU/GS+I3XEaVMMtqUADyX+
         7njg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:reply-to:date:mime-version:cc:to:from:dkim-signature;
        bh=CdHYoa39rErGUCXX9Rfx9X1/LsiR8x+PcD6O5/vrOaY=;
        b=DVrij9VYqhnMY+OmNmolZUMB7GehVxLUl8Qs2mjvg3LEaCOWJXGlunFB7zJSEe0Rh/
         /p3sZXWPlb4/env/seeUF3AUVEMzdFQvVfTxH3mHTreuv+FuNzU0BFHS7p2nUDv788Sp
         wicGjyWxaVucv4rJ8tnfclpSi7vrl/N6ue/EGqDnNaITmsJ6Npm9KdoYYrYR1MRz3MZs
         K+Tdd4M8btbmXdId+0AiwNOveZqpTmpoqiZbJZfIg+BkM+MF2Mpz2Z0JhcofIQAfW3g8
         KkiHrEEs471pZiQNRnmDnZxFb+ydFg1vrQv5C+qEFlpY1/CK7iA/aL9HnTQAtYk3SMrw
         eZjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bZiP4Vqd;
       spf=pass (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=nahwanngaycra@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id r20si17677edp.3.2019.09.08.19.38.29
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Sep 2019 19:38:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id o9so11593875edq.0;
        Sun, 08 Sep 2019 19:38:29 -0700 (PDT)
X-Received: by 2002:a17:906:b2c7:: with SMTP id cf7mr17551525ejb.124.1567996709561;
        Sun, 08 Sep 2019 19:38:29 -0700 (PDT)
Received: from f17.my.com (f17.my.com. [185.30.177.41])
        by smtp.gmail.com with ESMTPSA id bm1sm2720864edb.29.2019.09.08.19.38.28
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Sep 2019 19:38:28 -0700 (PDT)
From: nahwanngaycra@gmail.com
To: accessible@googlegroups.com
Cc: =?UTF-8?B?a2FzYW4tZGV2?= <kasan-dev@googlegroups.com>,
	=?UTF-8?B?UGFubmFyb25nIFNvbWhuaW5n?= <hvanyou42@gmail.com>
MIME-Version: 1.0
X-Mailer: My.com Mailer 1.0
Date: Mon, 09 Sep 2019 05:38:28 +0300
X-Letter-Fingerprint: ftZ6izsJEKdTgFghNO4I8CTOOB4WUMJE
Reply-To: nahwanngaycra@gmail.com
X-Priority: 3 (Normal)
Message-ID: <1567996708.553228440@f17.my.com>
Content-Type: multipart/alternative;
	boundary="--ALT--GvSFgQ8YwPSDqeAuzhfMDqOkgQQtjhqo1567996708"
X-77F55803: 68A6F98766B02875A0F21CC061F2095323D2FBEB2644075C17E427EE592BE230A952F8E506048BA2041A55C51A45A91E7685F5E470DBC402
X-7FA49CB5: 0D63561A33F958A5F98C421B66A6D60F3F67CD8310C4AEA38089B66D64F1543B8941B15DA834481FA18204E546F3947C1D471462564A2E19F6B57BC7E64490618DEB871D839B7333395957E7521B51C2545D4CF71C94A83E9FA2833FD35BB23D27C277FBC8AE2E8B2EE5AD8F952D28FBA471835C12D1D977C4224003CC83647689D4C264860C145E
X-DMARC-Policy: none
X-Mailru-MI: 800
X-Mailru-Sender: 5062038AA4CD0F5AB388CB007451A4F3DD9DDCC27198972DBFE89D9DB629BB0FD678C6E74D868EF25ADB52837C3B5A3C2236D74EC9BC5AD0D15821E16666CB4522DF1A08BD40178C22B820C1B2086D890DA7A0AF5A3A8387
X-Mras: OK
X-Spam: undefined
X-Original-Sender: nahwanngaycra@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=bZiP4Vqd;       spf=pass
 (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::52e
 as permitted sender) smtp.mailfrom=nahwanngaycra@gmail.com;       dmarc=pass
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


----ALT--GvSFgQ8YwPSDqeAuzhfMDqOkgQQtjhqo1567996708
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable


--
=E0=B8=AA=E0=B9=88=E0=B8=87=E0=B8=88=E0=B8=B2=E0=B8=81 myMail =E0=B8=AA=E0=
=B8=B3=E0=B8=AB=E0=B8=A3=E0=B8=B1=E0=B8=9A Android

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1567996708.553228440%40f17.my.com.

----ALT--GvSFgQ8YwPSDqeAuzhfMDqOkgQQtjhqo1567996708
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable


<HTML><BODY><p style=3D"margin-top: 0px;" dir=3D"ltr"></p>=20
<div id=3D"mail-app-auto-default-signature">
 <p dir=3D"ltr">--<br> =E0=B8=AA=E0=B9=88=E0=B8=87=E0=B8=88=E0=B8=B2=E0=B8=
=81 myMail =E0=B8=AA=E0=B8=B3=E0=B8=AB=E0=B8=A3=E0=B8=B1=E0=B8=9A Android</=
p>
</div></BODY></HTML>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1567996708.553228440%40f17.my.com?utm_medium=3Demail&u=
tm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/1567996708.=
553228440%40f17.my.com</a>.<br />

----ALT--GvSFgQ8YwPSDqeAuzhfMDqOkgQQtjhqo1567996708--
