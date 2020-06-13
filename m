Return-Path: <kasan-dev+bncBDCOXMNUBQIOJZ4T64CRUBHSW5VA2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0769B1F83FD
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 17:42:29 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id z10sf1868217ljj.5
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 08:42:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592062948; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tn00BT+E8D/hZbCZqY4WXzf1Nl17pH5qetSKmBBgdkv80fTEWW6fpBcVUdGogq6X4j
         aLJiciLdb4g+QEOa9Y+eMdRaPMKXOJVLiYSzKNt2DBtKVkE4rBX7W+TLYe/lIijnLSJS
         WcpuF1zFk1CgOX5ruxBtD/iWHwQsW7jZLPy2HAA2VrAyP9Sx49KMfI5fU2pTazaKTx03
         ZzuB1Mw/TW8YQ1CYvxsrd90MazLDkwlBgwfpORYpuyQFqb1yEgnI3zncuYpV1i2X9Hfv
         0pWgdc+ZpOMCX5BxmkG4KRiUtAkAWpr5uJlyh/3pW77MruHfRQAq2DJbGhWoXCSGX/lB
         iP6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:references
         :content-transfer-encoding:mime-version:subject:message-id:to:from
         :date:dkim-signature;
        bh=Q4AhX6l7R/F/MAmiOMe6EcbHpBy9JsvUdKZ0TGS4YWg=;
        b=tROPik1mf1natEJKJUL6bhn00Y5UUQZBzKeoQfYnTUQ9uexw9l5I5dL4w+sn0O7JWA
         Tf58gnwh4BDlwzEyhblTTmB/8YKscKX1nC3ZYNvXqLRlMOsxKtVncwkJxVAuUXIBWgXA
         fq6cdB3V1Hgd/Fx6odIXjVBJY6ZQrnRzv1wxIws5hs5WjZAw1BiynlNG8so942Ugnc5A
         8tp5pXw/vfPtY8tNtgMb3w8UKnRMIxNLpFDAjWlGkloHb9WINB9JkWEKKQh9DYAW4klQ
         +ErrySqKF67UrtpQvwg2HXVKGGjfrLvBDMA1GdQc8cM+RnuiJFLwrVa/sUMlfsGy8k9z
         o4Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=V0ZP3hmk;
       spf=pass (google.com: domain of rose_gomoo101@yahoo.com designates 77.238.179.82 as permitted sender) smtp.mailfrom=rose_gomoo101@yahoo.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version
         :content-transfer-encoding:references:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Q4AhX6l7R/F/MAmiOMe6EcbHpBy9JsvUdKZ0TGS4YWg=;
        b=oDk8EujHWSTI5tWhPIJx1BaHAOzEZkMagpzcwqkzture15+LUDA1PMbKbXox2JZnAS
         ziT+c7/zUAjV+1AdWG08E+YTmA73xIj6JIg2qhX9+/0WiIQRLorJgZTQ316nRrY8Fubu
         KoTgbmzFSvoG85EQQnZqDQLpKVU0eOyau4EntxGRsFedeBBAM5k7ITe8nzXhODdpSVjK
         5JNZwfdwpVbYZ6LstZpmu6SA5nW+HESVAFH6S1TX1YsXV1zSOVC92yD/bfe/fyHExLnZ
         R8Hd+MfnMzc1Rfg/5eaKPCUWRyn7oBvDnsrUbaCUcJ8Wddam1DxVes7pCu6DcuFIayOd
         fbvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:message-id:subject:mime-version
         :content-transfer-encoding:references:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q4AhX6l7R/F/MAmiOMe6EcbHpBy9JsvUdKZ0TGS4YWg=;
        b=Lr1NYJ3LZiUr/3WQFZUqk5emwFHVfWtniYlj6cISQdJ8PhGuXT8wl+OVA+2DLhLqOA
         rt0UFLVvmVavDOAzcw6+dSPmScqIFDrFPqCsD3fovNtrpzzD5be2K5z3HBrtSuM0Tdxi
         fENpXrvjWM4eBsKpXP4RJMFdo8S6jpGtUlBk7JArpaqvUoGgQX4/kqnShUtR16v0H0cj
         W5o6htTuZcrYApIvQeXtet3wrZoH+jNKUAgV7KF6zJLKgzGCNfeIek0SP7+EhfSnd/Gs
         T40r4a/Esvx9G4Nm8Vtm3nchaoD1aEVkoo/Y6L3txnJckybxjKD7RLN7vJUKTNoH5u4+
         umVQ==
X-Gm-Message-State: AOAM532AtM0hDZwfRj2q+AEcxyqsZU69a+uPOSDplI2qRduLcDdfRBoj
	yBDtUrJ62SngVkTED5DHkDw=
X-Google-Smtp-Source: ABdhPJxsdh58nDlh1sxGwo/NAtS3qF7p7yPAucSGi81DrK9R2CS53KEpjFIqScvQhQnDkKhXHrobgA==
X-Received: by 2002:a2e:6a15:: with SMTP id f21mr9065783ljc.455.1592062948518;
        Sat, 13 Jun 2020 08:42:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:30c:: with SMTP id a12ls1733304ljp.9.gmail; Sat, 13
 Jun 2020 08:42:28 -0700 (PDT)
X-Received: by 2002:a2e:9cd2:: with SMTP id g18mr6608808ljj.81.1592062947932;
        Sat, 13 Jun 2020 08:42:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592062947; cv=none;
        d=google.com; s=arc-20160816;
        b=pAJyetjZ14n5KZMD3jBjplrmEnhdvMKYw70oaeBTsqmVl1xHZpBGzCgDPwT9qtyDSb
         /Dv+WvxpfqJy88ZiVBICLe5hjnvEqDcAW+XkFQGegWfyhgQEw9YJVP86iRmuQDIh7Q4Q
         L82cMWf/Kk6+cfRKgSewRo1q8YjU+fu3SzjfL8mhkXWWm8oJ4Vfz7/sE8cGHNDrLIF7D
         0MbSplPN71ByFdrhIMWTLfdHXVWaiLPnPb6n8LH06ue0DN+21jVUZVW51pVy9TndI06Q
         xNGy/d2zz8tgJgtc3jzUxHRooDnh8lbd0lcNfxhxfG/1+yYvgPic/8AtL6thtHMI7r9u
         NUKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:content-transfer-encoding:mime-version:subject
         :message-id:to:from:date:dkim-signature;
        bh=EdQ6J0sRRv3XBxt3j7IlulUVvRg4uKdicik//r5GkY8=;
        b=cZYYO+oRO6b5n6LHgzTtrmwB9rjm4VXwexv53gzkVhHfhJ075JWfNw7sCPCtbyFjKJ
         0IuhDcDRhbGqJounF7bQHqLg808zMkBOCYmcqJvXAkrg7MUA/aYSG0tiqoSByrpncRle
         RUo2wcVnDwnOyFaPPcQFYvQ39X/8tGNrK8B0IZ0p0rGCCH0+pxrT8nzfpx3KWVRf26BM
         Iyxu3kQi5SH1Y+IqdFTtwlWgYd91va8Hn/Xf85H1sWA/XO7se6TUP1QJQqBFI40hb9YF
         Gn1RJZJq2NmWO3wSksvRhAgAsU1Iz6rshdCPIur5Txem7MCGsp84K/zWUSCpt66MX6Rc
         eYZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=V0ZP3hmk;
       spf=pass (google.com: domain of rose_gomoo101@yahoo.com designates 77.238.179.82 as permitted sender) smtp.mailfrom=rose_gomoo101@yahoo.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
Received: from sonic309-24.consmr.mail.ir2.yahoo.com (sonic309-24.consmr.mail.ir2.yahoo.com. [77.238.179.82])
        by gmr-mx.google.com with ESMTPS id 194si87175lfl.5.2020.06.13.08.42.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 13 Jun 2020 08:42:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of rose_gomoo101@yahoo.com designates 77.238.179.82 as permitted sender) client-ip=77.238.179.82;
X-YMail-OSG: ABhXdfIVM1ktZvRLmN7hn6VaE7xXCO82cYJB2vOTQFNij0_8gnxZNgCDOlRQyO1
 M5722DJyFfkYHLeEHEmmxe23z1Mvn1FhXyD6tlpj_0HWEFjimGQDg_C2FPut6FeMm_yFAIF5YgTe
 WU750FHbM0pFtHfvkqHEcaeUWh9cRj1phT9_VLlzAOGlRfYDYx60zq1tO80QSRzIQbqYucoQp1Xi
 S_UBLDmyo4rMFDAQGo6qVqHrzLg2etU4iM79w2xWmUIQCVNq0kzGAwuYD1FR99ve6oszqmR_Z9Z_
 stbtFrq5VdyIoCE8X7hloTu25CJ2qqKkz8nsV3U8yT1sgIP8n3rpU2gWNDu0qQATri0wSvQrYkrk
 vew50AjWwqjoZSucd3uw75PXVKYJPzi7Dl1zcRFa_Vu0BV3tAFQu529YKuwa1JofrycogTQMOjvs
 97a8LdQaNTWkdwnZR78GMMM2ZiasuuSSSyeL6THBHoDI3DnW4HsscMsum975GnXIVuN8cUcLfXRL
 UhmQAOqohgekKz3k87ece9HUa_av_ONXIyFQuhdt.J3t1J_8ulT6ojBbUqzgqE.CsDTe7AXEr4Pn
 dVvrlwAAQcOlKri6a8xq6mfvX9mD5Tz.10XhUyhWgzIXXFsd0rA5z0eNJX6O3dqFrH_Qgac9Qu6E
 9ZBWQGf9h0k.pTxnDDWWDKPMpoCGltxY65Wa4r_IU4UTHX.TYigvZTWAozZ1f7WA_4vt9yeMFWCb
 sK9YCUr96MR0s09px0h8w2IvYSt4h5oxWoWJjmroYczzCV2Qbxtfn69oyPgiyJ5fBVC.tC.v_fln
 zRs9F7k..2lceuj_1A8gyN6pxpWhFDJuhI7rx2GaVNp8s9hCPUwS12vnMW7mYwRS_70c7NWyF4Pi
 NYaI22gc3NYE5KG9LPhEubrTZNUID9N0XVfkBveX602qRQE9lbFN62ncNFXIlShMhJ0q16wPs3ox
 9rHr4xOVA_JNb9AZykwsgthsm4WUO5zPmk8qR_XJIF8iImt215tOpUm2rfXvJy7nFXngJ.fVi6dW
 9JPhPhbglW50vy3JNKJd.v612TanqscOyrwGEAC9JJJZotYZZWaFZ6tcjacNim33w07SUjNft9Gi
 N0WraW2VxFJhSfFIqq.YpMtWT_KH5CaUmzUEPNk_JfsWYy2mhnjzf197tHUH7c.jaBUVcLhjZ5H.
 oApbsDJ9DkrgtORcxsaghuavzf2sp70PHWRKWfzoF42gumsFxlcnrAG0F30ldS6BePVQ1OSHOw09
 M.2s0KI3NGb9IigaP07YncP8BSacxclXIEwJ2ISPQ0g.G4mo5qlZS_SNoAHRQ0a26Hio-
Received: from sonic.gate.mail.ne1.yahoo.com by sonic309.consmr.mail.ir2.yahoo.com with HTTP; Sat, 13 Jun 2020 15:42:27 +0000
Date: Sat, 13 Jun 2020 15:42:25 +0000 (UTC)
From: "'Rose Gomo' via kasan-dev" <kasan-dev@googlegroups.com>
To: rose_gomoo101@yahoo.com
Message-ID: <2011529051.456701.1592062945614@mail.yahoo.com>
Subject: Dear Good Friend.
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
References: <2011529051.456701.1592062945614.ref@mail.yahoo.com>
X-Mailer: WebService/1.1.16119 YMailNodin Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.5; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2)
X-Original-Sender: rose_gomoo101@yahoo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@yahoo.com header.s=s2048 header.b=V0ZP3hmk;       spf=pass
 (google.com: domain of rose_gomoo101@yahoo.com designates 77.238.179.82 as
 permitted sender) smtp.mailfrom=rose_gomoo101@yahoo.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
X-Original-From: Rose Gomo <rose_gomoo101@yahoo.com>
Reply-To: Rose Gomo <rose_gomoo101@yahoo.com>
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

Dear Good Friend.

Please can you help me to receive the fund I inherited from my father to yo=
ur account in your country for business investment? Right now the fund is i=
n the bank here where my father deposited it before he died and the amount =
is =E2=82=AC2.5million Euros (Two Million Five Hundred Thousand Euros)

Please if you are interested you can contact me as soon as possible for mor=
e details.

Best regards
Rose Gomo.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2011529051.456701.1592062945614%40mail.yahoo.com.
