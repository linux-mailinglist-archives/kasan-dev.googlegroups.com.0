Return-Path: <kasan-dev+bncBCRJJYWFTIEBBQN6W2GQMGQEA6EGD7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 45AAB469029
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 06:27:30 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id kk1-20020a056214508100b003a9d1b987casf10670506qvb.4
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Dec 2021 21:27:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638768449; cv=pass;
        d=google.com; s=arc-20160816;
        b=DshVfAgnR+oJbUp6VjFA12qx6mPpNU/TAWodkrhSvIUTBx2qzrpYe+V1HKp8jk34ck
         Wl6pnN/prVefLhtP0fEuBcZrnnJek/ScMNGxAPdmifyBAwF1YXOi7mPhAO2JrqqOpzy6
         Q71uzI/A6U4buO9zZF7ILm5Z991FvXHUb7URtKHKJggRaYRCC4wDQrMCSgzeCmhUY+ir
         VPczhaMaH6xXoOxJE2sBkHEByOtDimAD/aBciiM+egX0QUgAXQ+iZ+G8mQAnrqjnmZ+P
         3QoJpHx5zhs/Sj/E15drIaR9+3YnCHT+lGxSwsNm8/aEvT/EzYqsUT7imq6gvAxom7Is
         NAWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4o4XVD5ViRnMU0QB/nxGWprbSC1p4RxCqDj/wX78W2o=;
        b=ODU3ihkyzs37k99jEDEOkppyp+OOgKSHMBR4B1vYwTBIFP+ommL6kctLAXxH5g4rF5
         bOiM9NMF+308LE6ZpwRqttHOLv44NbgGFdq2oI19miVEsgjN263qmN1488dfO0+2D/Ae
         WfFthh9BGbG0hbYa0LeXpzkvDCNa1aOjP5BKEYPkme4U4TTnAMP7QtTIDjgyFDY9WmmF
         dMsrKQN3u4uCRmj64qABb480WyOeoNDgDnWb+uVGdR8k0x5PDFWCFIs2meF6UUA/97Xf
         5nYIpbzHi/h+CxlA5I4Gx0MJVxqSyJY0U754lbaza+J1JaRu8juLi44W4+/xT59XKJW9
         QUQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pKxIncBH;
       spf=pass (google.com: domain of sofficer520@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=sofficer520@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4o4XVD5ViRnMU0QB/nxGWprbSC1p4RxCqDj/wX78W2o=;
        b=c0EGiPw3i0f8qaZ71m15/WTR3/lhXc4pi7Qfp+MM8WjYOwBBfT04JV+whyErEMnhNC
         2iFJBq+jHllt5xgVsvkVnnakhKwpRLkZeC3J+wSyYzT5UrYWoaYunTxg+kCJemkx18zg
         +WLpCDgDkDhRaXLxgOeAIZWA08qf61KbSJZZGp+DMV5/bOzYEpyhqyeGxi3VNByjifNO
         hQMyiiTvSW3gS9A0LCJh6lz0WJXMRdvdkn6A3q35Ua4bhPwf2PN+Xv6HCNqjFpGca4w3
         x0ex714zy5aX8WSVBt4hZAUEo38FsOWOTf50e7F3N6OZlMvEkzhERgJGy+RAvD2fD9uh
         aKJA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4o4XVD5ViRnMU0QB/nxGWprbSC1p4RxCqDj/wX78W2o=;
        b=jucNUfh5ui3kr2qIPGUc5BQCHS2dlZRFOsSXBplb5aonS1iYD5Jdls+phT9YHGd5A1
         AS90/FkBBJsYrAa5y8zQAyyw+S8K9v20i1TLL8+mVcXyXCYYXvZv9stNYLWd7OGBYAHD
         /VGfMyaoiYHTJR4vYzRB7dJAZlZUI7l+LKJZaSKLfd8l7gLr6yglIhl3Lh+hReZeTXva
         djSj24jtH+TDbdgwbOTo96IZ6+vMbGD6+KU5YmStecTswJDHdoQGMWqKTCVryfXMensv
         iUJDTg6fkiPrrlGt8nPT+BvWu45gDfBYVKyrw3/HJr2AFKIFpFpo6FHlnGACpLxkUMU+
         B4Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4o4XVD5ViRnMU0QB/nxGWprbSC1p4RxCqDj/wX78W2o=;
        b=zJPTDNRZgiEpu6TGysaTjjg6bXFCqh2swyU4vFwH1jvbQEG9d20BUXzv93nOdpYqkW
         btJVdJxW5fpgj0hondJJoEIUcsUmo6YFsLsWn6tz418o+9PJB6q+kV5KDbxCNczqE3l0
         fNpLcYH59cHteQFmUZaX5RIxYVbWd3bdtzRTygY5Szz+gmlxZDghR2N36YT5UtTPnUK2
         KU+AgMwiJ3Tie0n0/kFUEe+qgCQq/IhG+FFDZRSIEtwEosdq5yv68VikngUI+j3GUwci
         fT3r0D966sGzhemiovjPQDw1YfKxvD5r8dPbRB8PFnRfsS3195/8GLGJGovaOH8aF9m2
         7NQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530feNsJIiEl3R6UGR5/NAEV8w41p2+1csdC8n8XxqAHQHdXmSMM
	g2jWPYVNjgHzDo+ONVZY8Zc=
X-Google-Smtp-Source: ABdhPJzPPxqJGnI7bhYNqN0gRcXVJMxCiGiVoNn96aG0q1YPOIyGK6KBzIdEw/d5k8U0ZVGOisHe+g==
X-Received: by 2002:a05:620a:c4f:: with SMTP id u15mr31082923qki.565.1638768449240;
        Sun, 05 Dec 2021 21:27:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a0d:: with SMTP id f13ls31120qtb.10.gmail; Sun, 05
 Dec 2021 21:27:28 -0800 (PST)
X-Received: by 2002:aed:2022:: with SMTP id 31mr746165qta.238.1638768448700;
        Sun, 05 Dec 2021 21:27:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638768448; cv=none;
        d=google.com; s=arc-20160816;
        b=bp/Q3C38laOjbXFT8XnxUHOUP2XOj4+UyApBb+ZIeusdMrFvx5RDIZ7t5S4of3RlWF
         lBy5w2JD30iXCedlTRMx2u6bRecVjke9U9oAvWgMICkXILBo3WeJRm7gAc+H0LbK/Dew
         mcAZz/tsxLRCTVuCJ8U/gQTCO4l2ll84rFLEreQeG9rXaKYX1xT8mRhJCzw5n8pY4TGo
         B2kBpX+RYmxiBCSbS64Z+yMZ8ZICguNfCFDzMUYnewea73U3xYmX8f+YJOkcKYy7gvUH
         IBg2Ca+kc9LBH/sS1K9lbQv0VbAHQoXKSzvibOe0rBLSrf2bWYFtXJimlratMvnupZcX
         PXzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=HUG0lS42HmoNcIY/gM5eYXfXv6XsPHSsiS1A4LAnmkQ=;
        b=SkbirFjHGAhGWKmqxyS49vN5s+1unCVkWgx9kyymSPg6X7a6w5e5/U+LfJa7+bYLHr
         kNk4LcH5RwMbkYhOwkL9ht4NSGPj9DVMT9PygCZ8wZ1VtUwdXO2YzbMrvsR5rvpDgKuE
         YdxSrd3VPR8SFJ0z8dNVDUEpZ+7HLlh1qtErpA9XOkkIFk9lq8tI2/uzW5/PugoaufjO
         A8xxcikFYEHUMVEKG2njsF5EMiWNjb9k0o7HQNNc/eJKqRWClEyaTBGOjTntcmN2kKAF
         43OeEuk6cZnxhXQSJSXI5+vM5S/lbmj4yXdJXIGaSzxXZoK+WMzmRV3f0lUJIx3DvvNG
         3Q6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pKxIncBH;
       spf=pass (google.com: domain of sofficer520@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=sofficer520@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id w22si2239791qkp.2.2021.12.05.21.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Dec 2021 21:27:28 -0800 (PST)
Received-SPF: pass (google.com: domain of sofficer520@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id g17so27897497ybe.13
        for <kasan-dev@googlegroups.com>; Sun, 05 Dec 2021 21:27:28 -0800 (PST)
X-Received: by 2002:a25:ad9d:: with SMTP id z29mr40045245ybi.281.1638768448295;
 Sun, 05 Dec 2021 21:27:28 -0800 (PST)
MIME-Version: 1.0
References: <CAFCTF0Caxg_D6odawo00QywtwYFbump=uqXTu7+-11TxtC1V-Q@mail.gmail.com>
 <CACaEXP1cVFLkmUG4S1V5c45xoFgsCVfUaGE3kwX47BUouvNXbw@mail.gmail.com>
 <CACaEXP3c_-j07BHvt8hW4iPSOQng=kXQiwX-MjEb+dyh=DdWkg@mail.gmail.com>
 <CACaEXP0V73w+q_6WpPrT_e-ANgTxY8p4MSwcq3emoB=kc--afQ@mail.gmail.com>
 <CACaEXP1HaZ=xxowEjy2_bUMhEfyZxYXXUFp1x7k1YgDSCdWa_w@mail.gmail.com>
 <CACaEXP3wmVVx2Q4Afq3gjxnQAhAHTNSzwuOsX7xVwAM29ZJX=w@mail.gmail.com>
 <CACaEXP3cetFAF2mnYtYYh2iQ+wfiYZXy=BaOQh9e_tDk1w4URg@mail.gmail.com>
 <CACaEXP2Nk962+WNmkuYaDz9_V7no2jXkuJsx2KuiE5zhG_Oj1A@mail.gmail.com>
 <CACaEXP1BxQGPDcFQDXxeZpyL-L3fpP1=AOnXAiRDrO4zSBX-hg@mail.gmail.com>
 <CACaEXP1D=Mo-Jwzubye4x-fEF86bUPmjMEBMThAr31xGwTsaBw@mail.gmail.com>
 <CACaEXP1chYZWWKnf+zUzCzCmZmLNRP1fhzB3u=EzO37O3t5_pQ@mail.gmail.com>
 <CACaEXP0BCa8=xnXXeBMgiUxWBR+iNetBTNrvkKFcH+Ch+vvokg@mail.gmail.com>
 <CACaEXP2ZVug0ZoDEGa9DhFufdAshhUNJo2fJrwFeF2psmjivJw@mail.gmail.com>
 <CACaEXP3qMb9N3WrqsPwocNagxcOW4stbrd987Vn-hNJpmqf7eA@mail.gmail.com>
 <CACaEXP1QEta1QWPQqyRaWkgf1egzb1OxwA4gRhHjWxbMQw9sNA@mail.gmail.com>
 <CACaEXP116Ja3aoQKRTDknTti2uJHq83c1fW1ThRQKbQtBD91=g@mail.gmail.com>
 <CACaEXP3oMPV8tVh4uRFNrG3J41ibOoZJ7habOB4ENDFjXZcuFQ@mail.gmail.com>
 <CACaEXP3HmnTd88=ybJvcX7FZh5OMbpCKqS-SSSYmXdzrZovEZQ@mail.gmail.com>
 <CACaEXP1oN_s6ZOi8bbE8n0rUwyDd=ndkOXc+Zgxgtk2ULZ_uTA@mail.gmail.com>
 <CACaEXP2VGSO8JijvAxk7DczVVA4n+X4yDOF9_284FeUrONyCpQ@mail.gmail.com>
 <CACaEXP2zTUyTWnh2_A8TWxDP0pXd+1fXqWSXYVCBhYbM6pjMHA@mail.gmail.com>
 <CACaEXP3kaeGTdf9QBqAh-eyOVVgD4K0ic+1h_i5F2bCgCoA=TQ@mail.gmail.com>
 <CACaEXP02tZ1xg41TEjzhuU-mMyiCVseNtpoV4V41gxRUUJwAcA@mail.gmail.com>
 <CACaEXP2nX4s2T4xkZnRYKfNCbvOw-B9TV=NYfoaw3NUH=JCyRQ@mail.gmail.com>
 <CACaEXP39Ru9MvXzJx-O8xYgn7FdR1SZfERPArbNkCQ8he64vQQ@mail.gmail.com>
 <CACaEXP0ugF+uY9HwvpjjFSFmjgceDte8fdVkxT51Ywm7ywiJ2Q@mail.gmail.com>
 <CACaEXP1r2u13D4OxpYJhhNa5Ps8fQA9G7+PXSoZFocPavXam=w@mail.gmail.com>
 <CACaEXP1M0ztO2WYhoYpC_8UmS+UefwwEhJ07a_BkWZNPzneMhg@mail.gmail.com>
 <CACaEXP0e9OV1M4Z5ibRN5vZUN1+GBGWcwiq0SpBRrSj4Jjt1kA@mail.gmail.com>
 <CACaEXP1KtgbC4RiYXTA_WDDfn87wUy=x_-3t=7k=JbNtUY6DcQ@mail.gmail.com>
 <CACaEXP1Rt6PzvXjoEOPm5MaVKKiD9-FZNQL3esrCAxG3HKp7NA@mail.gmail.com>
 <CACaEXP3HHbppymFQ7Oa_v3iQPcxvkQJ-S93n-nLidtajmQk=EA@mail.gmail.com>
 <CACaEXP0xVL9BzAeSA8T0YijnB_iER7hw-OXJWht4omP6e+W=3A@mail.gmail.com>
 <CACaEXP0fyEAv9zJL_O3qCbn9ZRH_4CN1LvYqkcLuqeQ4ZSTpoA@mail.gmail.com>
 <CACaEXP2id-cY9aEMyNO_vwfPgKUoF3+4Q8=cujt7=P19BCZZPw@mail.gmail.com>
 <CACaEXP0HczOVL2c8VOaSGWY6-CNgQojWimUR7Hjb6a8bJZjezg@mail.gmail.com>
 <CACaEXP2MU+SF9J_uk=f4KUFheP4Uw66uyAmmxwD4s_hzLauEPQ@mail.gmail.com>
 <CACaEXP1hvmcmyG_VbcT7GiZ1X=0-OgZ6abdwG6u67_BvQ2VrVA@mail.gmail.com>
 <CACaEXP3Jf-1vFMp2ij1ThQ6zHkT0cZCqiuX7fQid+G46FrobRA@mail.gmail.com>
 <CACaEXP1pY+LD1G7ore1dkMQzUvh5M5FkuMrpNagAKmKyqTcJRQ@mail.gmail.com>
 <CACaEXP2DeRyu_BAcFvUg-0PYN2WQ3LsUEOA+5N51vDQzNXnABQ@mail.gmail.com>
 <CACaEXP1N_bnW=3FSCkFb5SbHOwwOfFixaQVH=HO6+OLRqgwbRQ@mail.gmail.com>
 <CACaEXP193+b3COVq6FdBV5e_+tqGo0nnpamGGDmoRNWaCSevqQ@mail.gmail.com>
 <CACaEXP0tbXO3mMqo0-hwXgFm6Z-Bpwup3MjhqGYvvbuz63GcTA@mail.gmail.com>
 <CACaEXP1OGCUCYtHhfDrXVmS1qV=4vCuZADGrexqm1hwKDagdog@mail.gmail.com>
 <CACaEXP0JOEcej4ZL1TeZky1ymAPdvADXaiWA-JkRWdnUCHvs+w@mail.gmail.com>
 <CACaEXP2t=-r9Hhjk6e9dqc=8MFMWTopGmTaqAa_LnEfjFNn0NA@mail.gmail.com>
 <CACaEXP0VHKh7WYNCGWjRoXPtA-79p2DVp5RxTE7pcPWiiDi2rg@mail.gmail.com>
 <CACaEXP3cKFjBpi0ZX-YP_v7bmYrAuAFVmvd5y6+L_2Q7+r97+g@mail.gmail.com>
 <CACaEXP2eGr__xGNZ8jkGAmdqsXrHDH8DeXL=k2ArPtW8b=0tXQ@mail.gmail.com>
 <CACaEXP2GTQa+uaD0FM2HDxQANHg+uQ3WwwEEUPOjFVcxYSJyig@mail.gmail.com>
 <CACaEXP1Ws9XQOYtAPLBzsm5y6X3AMoDPPsY6y+u-iOU_5XtCAQ@mail.gmail.com>
 <CACaEXP3sY5E5J2hsXgx2CRs8V=+2euec+s1CGET4QdUQiQpO2A@mail.gmail.com>
 <CACaEXP1PwPaO58hFjPY0B6-OLjk+A-V3tdhvUsjDb3JicfiYjQ@mail.gmail.com>
 <CACaEXP0y_W7OogCMLx7Cna7kp5-XznEXwFCbp+ZDAa6DDMc8Ow@mail.gmail.com>
 <CACaEXP1ZTWRmBtNbE=RudDMMujEy+u+NmH4XJ5UrdyniqYpFxQ@mail.gmail.com>
 <CACaEXP2y8kLvAcgueGXnDuPiYJt8k9s9axuT+=8j_Uq9zJJ37g@mail.gmail.com>
 <CAL0618sd6PcYrMJ4iuQPbr88j+uFtbJGUJnE2v+5L-2uKRTz9Q@mail.gmail.com>
 <CAL0618tGu5By0Eg-7k726zBEgzDT-Y9Aw9tQd9EK66f4NkzhkA@mail.gmail.com>
 <CAL0618u+yRZNa0vGHchSakx2A++Upf9h9x-y=mDn5jn_-J30+A@mail.gmail.com>
 <CAL0618u2N0T5usCTBMqEjeuEn+AzXAgz-v0frfpDXZOFKjQpjw@mail.gmail.com>
 <CAL0618ukhE86i8Yrf2AH8WS4oNjUr-_8wSs+6jeuZPriCksm4Q@mail.gmail.com>
 <CAL0618vtfzHhVemYR=j_JAbvbz6ZV3vH0=quvuSvqPH7TSNEeg@mail.gmail.com>
 <CAL0618u5k1uzo4k=dY-yUezv9bPqUYHubWD2LF+9HPyAnc3qtA@mail.gmail.com>
 <CAL0618vTwO7FAr+iaRZdTggsF94oG6kex1Gpv=woPhP=3+aNdA@mail.gmail.com>
 <CAL0618tRykXXOv+-n=5KFd=HvhKtD=yh2huO8Sh1J3OKK47iEw@mail.gmail.com>
 <CAL0618vkfedKY3fiSumzr_T8Ybm_XVnS0keJ3ZGjUL96yZrwUA@mail.gmail.com>
 <CAL0618scjkkeR8oPFBA-cHsj94OZZu3xr7BA4kQnU-4BzrP-aQ@mail.gmail.com>
 <CAL0618scqE+cs3=pXZr3_NWWQP7Cv0srMM8b-+0PAnhT9v+w-Q@mail.gmail.com>
 <CAL0618u=j3wR+aWLBx-EsU7aFDG6EFjLGhuPYFrfq20N9fNu9w@mail.gmail.com>
 <CAL0618s25dRVwbhwVUzsnud0zsqwm80Gosq2Hs4sOmppn_KuRA@mail.gmail.com>
 <CAL0618s06AspV-=hS2zrv3dnadbdHin=Fp3-iSzAUKBeC7a-AA@mail.gmail.com>
 <CAL0618una8J5gr1FH7xwS_r7M+5KACUfaJFzWf5qCASLjbZYOA@mail.gmail.com>
 <CAL0618uW63F7BdaTLujHcPj3n9bRu+8=hMZ_LzY62J-5dQPANA@mail.gmail.com>
 <CAL0618uYBfpc1LrRK7yL8Ya=gSkkCoV99b=Ks5eu1UX9d1ieyg@mail.gmail.com>
 <CAL0618t1D+CXn9AXGCUJ_5fu+bV3v5GPst=77ZGgkJbQSNY0sA@mail.gmail.com>
 <CAL0618tJ7ebvcZyxYJPbrp-=GrOuwNY46kZJDc=cN2oZ0Oc2XA@mail.gmail.com>
 <CAL0618tqmLJOQyz-d4xNwC99qnfiFwAOTocMEPz-9tDDf=FwhA@mail.gmail.com>
 <CAL0618sy1PXkTkvAgqcHZ8i+LKwZ_RguRZE+SQtDwQTUuyhGrA@mail.gmail.com>
 <CAL0618uv7+qfr0OvgCCwYV+oKfQt3gZFk-nWypWFW39qb=Jgrw@mail.gmail.com>
 <CAL0618uaPzRjvbHP8okxs+TOcuxqPYuF=8QEHuopQeLphLKKkw@mail.gmail.com>
 <CAL0618ughH322prj8rW6Rvc13m0YWY9Eti5HJdJW5MDcQ5BBgQ@mail.gmail.com>
 <CAL0618vXaVwFPKHQLtY_gPVsgWtuC3CayRBsJcPV-ZwooKzYpg@mail.gmail.com>
 <CAL0618upDJM+d1stO-qvq1c8HneR4wPvcMmVHpCqT_NB-Hom8Q@mail.gmail.com>
 <CAL0618uQCBq6GLgMe1=J_76dR7jbPKUHymd4xjs6U6i3deS6dg@mail.gmail.com>
 <CAL0618tOrWJ+T6kVChxZR3RP+P6+hM3L0ALzhAPSUUcbZfJz2Q@mail.gmail.com>
 <CAL0618upADR_c4pg1LXa_dxYw4cAxxK3CzWqtzpt0OOWg52mOw@mail.gmail.com>
 <CAL0618vn6iwY7aL6kvjd-yPr6UwtcpHW5s7wy9GR2G_SpMTqwQ@mail.gmail.com>
 <CAL0618vciEBTFY5ZFsvNF7Gmj=_YkUofm+Ygn1xP91yuYhHm8Q@mail.gmail.com>
 <CAL0618u=HYeF1aH-F-w37xoKkUcbsaXn-jvK_SQz-hMfo-oyxQ@mail.gmail.com>
 <CAL0618tUB8n+p5mfmszTn1GGkub8OexW2a+hyoSyVYfhLBefcA@mail.gmail.com>
 <CAL0618ug5x5_85HMHQYEhjb7ucRjVwkf2H2_e9oAjHX1q8spow@mail.gmail.com>
 <CAL0618sbt51_KTQtc7RHpNmVnBDEjHbSXQx_YvzJT=im4BNgQg@mail.gmail.com>
 <CAL0618vK1kF85qUbULRFs_Y6EmPxrGNkvLL=VmE3LoaGzHb71g@mail.gmail.com>
 <CAL0618vAJY_a9e12oJ2HhOh1RNC7Ea5uB6ecid7SW_1bcurw6A@mail.gmail.com>
 <CAL0618tfubOXiymVACX=4k=747GX_FdctpYE9C9x7gu_QoCcuA@mail.gmail.com>
 <CAL0618u4GPrDwjinpZhysR6MzUQonUtvMf7soRRQe_5Z3KLXJw@mail.gmail.com>
 <CAL0618v1XL=tNEpqovCd+H6ZBidsueG+r6cdE+TQnRqTGsxNpA@mail.gmail.com>
 <CAL0618vfignVZ6CLZ2JNpfh5VtOSJxhr2AjVeW0YAFfBSqRx=g@mail.gmail.com>
 <CAL0618s=USMnRMtM-yx4=TjPPukJ-33WvphJN3Vf4-cLS=imzg@mail.gmail.com>
 <CAL0618sp4DBmw7NPm9Fxa+Leo8AzXwXiea85wofXFMhZ5z-43w@mail.gmail.com>
 <CAL0618sJCrKM_DfEcmNQzsrwpwkJuURLUPykQOPuz1fRf24Ohw@mail.gmail.com>
 <CAL0618ujRmXu3oPyYpORGU3dKEpMXefw4Utb1YGwzTQbTMBEyg@mail.gmail.com>
 <CAL0618tFWw-+uRR_ag+ptpRp5CP30QAvhALNWPvprF-JDogG2g@mail.gmail.com>
 <CAL0618sbDXmdJM5MzkDtD2w6H55Fw1YGsA1pucSsSEMkNWyExg@mail.gmail.com>
 <CAL0618tPen1HtqJefuu70zVw_KAFHG5c6bZnNkH9sOYQG=vAOw@mail.gmail.com>
 <CAL0618s-MK9fxGoD57iQNUPCTWCgmv5zO4-tht8UyHOmmt3-vw@mail.gmail.com>
 <CAL0618t1WnMmtNcDNmw3MLvQfAyvsCxC60+aT36Fna=5e0iQhw@mail.gmail.com>
 <CAL0618u1wZq_2SrukCN+3NJn_02M9cASHzuHkHcfGro+zj7qCw@mail.gmail.com>
 <CAL0618tTES3r0kuV3Epaa4hh-8wWVRA3kmbttCC3rEEuT2ZNag@mail.gmail.com>
 <CAL0618sM5tBb_dL53EBLQ7TS7bvo1-akdO_T1E_sc+tDTc7qOQ@mail.gmail.com>
 <CAL0618umV4CgCb_ACGQY6zP2c8nuQ8bU8N2Y3cFEwGRF2+i2wQ@mail.gmail.com>
 <CAL0618sj43cvLZv18wuF+BVM42AXO2S0dB0gfimYqCdC0-qD_A@mail.gmail.com>
 <CAL0618tSUf=qjB9xnMucR_L_PiwRbxiZD9aJAMHU97-t6wPsbQ@mail.gmail.com>
 <CAL0618utzNKYSORQp7NP93ADoaZmpu254ZAucpDgNTunBA-Spg@mail.gmail.com>
 <CAL0618sFcK0Gq21TmLm+APbmPaQn9hKLEvQ4ds+Xdk=yasbw0g@mail.gmail.com>
 <CAL0618twnGxK9=wM=zAmKXsZFTF8Mra_=p1HwtCHJPB7OjCxrQ@mail.gmail.com>
 <CAL0618uRfQsdnkWfidHrdJR2FpkffQBt7hAqV=UFh=cLYEOOXw@mail.gmail.com>
 <CAL0618tejSp0zsCi78z8-Uvv+HkyTn+KPp8ZpUfyGx_qdLu=8A@mail.gmail.com>
 <CAL0618uXccfTQ1XXG9zyE3F+yoqR=x18wv33kvA+A00f_o-3wA@mail.gmail.com>
 <CAL0618tLf2SbM-cHrTrs8X-JO=ZrLV=0fK6z3AGOnZ+XJQgMRA@mail.gmail.com>
 <CAL0618uibCCg2jnCF0zG-WynaMpM=Ey0zDSL1ZneaWGCrVPhEg@mail.gmail.com>
 <CAL0618teGdTQ-H-L27cn=Kkv7Oq5kXarxfTKRSg3xD02VfZp1A@mail.gmail.com>
 <CAL0618vd5X-A1T6cnj0N6hQgQ1Xop6Zz=v6T=dLOQ+syo-3V4w@mail.gmail.com>
 <CAL0618vYV3cuZuZP6VugFuueAU7fMAS4=CGtfAj-dyOotk_d=w@mail.gmail.com>
 <CAL0618uW6FH0cE5eYT3QRnYQPwq_3ZjHFWP=NBk9-vn_N9H1bg@mail.gmail.com>
 <CAL0618uF8_oRJ4wnky_fSvrsB2cfmFcaPun2Q0cc7=TzT6FVDQ@mail.gmail.com>
 <CAL0618sHmZXKGKPZFtdiw0AbyeA2MwEm=E_C6CT=FGnsVwk4EQ@mail.gmail.com>
 <CAL0618s3TDOTVpT6Vac3uqEjxmvoL1z6HZOWq7wTNbvAT_xuYw@mail.gmail.com>
 <CAL0618vxN6AUqmc+od5nQGtQFnNmPDooL962QDrUTt+45o0zzg@mail.gmail.com>
 <CAL0618uGFs5Soyztc4b9=J81dt5Mt=gjsUTFqsj-+j+FZ0HtTw@mail.gmail.com>
 <CAL0618vvd6Bkr37NWs0zgAA2We23oECdo7NyymV5y6mbBT-qmg@mail.gmail.com>
 <CAL0618uQ5W2iQSsdF3oM93c_kPA--03rJk0jOgRvrjnSVzjxNg@mail.gmail.com>
 <CAL0618ss_ts=RWCtqahKZOQm97SZtONqjjxeoReM53ppCnpGNg@mail.gmail.com>
 <CAL0618vio3++pAgVX9q75os3UCXOHny6ywDtsRn4_mKvHZL7yw@mail.gmail.com>
 <CAL0618sUAWEt1bqgNqytLQvaYb-TDs+R2eRFNrwoe4T6KvOmHQ@mail.gmail.com>
 <CAL0618uZWzkapS++ghQrqoqUjGh=_Vp+fGdrnoyMgtaCJB8knw@mail.gmail.com>
 <CAL0618ves6ZTJAuDzom-8Kshb2iRXUm_M0gJcUaMcoOW=J9QYA@mail.gmail.com>
 <CAL0618tpOfJGTKCQ8bWtE-XTzA0JG73QvBbPC4cL==KzZJzv8g@mail.gmail.com>
 <CAL0618tcKb13p6As2C1gD_=1p2bAiaJ7ijOc-e2NnGd5kXvo7w@mail.gmail.com>
 <CAL0618scvL5k+QSOuWAoJ46BMwZ48yEvvsLKANR4s49knxQ2ng@mail.gmail.com>
 <CAL0618vP0bRMhrj2MWcLvdsHME1d2Okod6B67_CKxvscyxD6_w@mail.gmail.com>
 <CAL0618uT2NqWd9-EH8vZC0Zcbk-dnqukEf44eMkLR+skBtC=rA@mail.gmail.com>
 <CAL0618tAaeDqNF6v-iE1kAZwzMYW4eug5UKi_Hh4OMB23-ZH8g@mail.gmail.com> <CAL0618ueLtJ0=Gn6m_HFf2srZ78h3SG6O3PzSJVue6K9Zuj2Xw@mail.gmail.
In-Reply-To: <CAL0618urZYAoe2um7tLPPFETbixe55h4DLfmegFYMXPW3ds6pw@mail.gmail.com>
From: HSE OFFICER <sofficer520@gmail.com>
Date: Mon, 6 Dec 2021 10:57:10 +0530
Message-ID: <CAL0618sEcGAFPB7Nvx_eUn9oYZTHGcxyLdoQ-oTrEfejjNsEDQ@mail.gmail.com>
Subject: (QHSE) Safety Officer_CV
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000003ad84705d273839f"
X-Original-Sender: sofficer520@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pKxIncBH;       spf=pass
 (google.com: domain of sofficer520@gmail.com designates 2607:f8b0:4864:20::b36
 as permitted sender) smtp.mailfrom=sofficer520@gmail.com;       dmarc=pass
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

--0000000000003ad84705d273839f
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

*SHAIK*



*Mobile  :   00919885220558.*



*Email    :   shaik.karemullah@rediffmail.com
<shaik.karemullah@rediffmail.com>*

*                  safetyofficer67@yahoo.in <safetyofficer67@yahoo.in>*





Respected sir,



*Fire & Safety Officer /QHSE Health Safety & Environment Officer* caught my
attention as it seems an ideal match for my experience and talents. As a
capable health and safety professional with a solid technical background
and a wide range of experience, I believe I am someone who will be an asset
to your company. With a proven ability to implement health and safety
initiatives that get results, I would like to explore the possibility of
putting my skills and experience to work for you.



Quality Co-coordinator to ensure that all health and safety procedures are
carried out correctly according to local, national and international
legislation. This role usually involves attending external QHSE meetings as
the company=E2=80=99s representative.



(QHSE) Safety Officer is responsible for all documentation in relation to
health and safety and you will be required to keep all documentation and
safety manuals up to date and distribute appropriately within the
organization.



I would be pleased to have the opportunity to discuss future employment and
look forward to speaking with you. Feel free to contact me at the address
and phone number listed below.



Joining period             :            Immediately.

Present location          :           INDIA.



Thank you for your consideration.



Sincerely,



SHAIK



*Please contact by Whatapp, Skype, IMO, Viber and Mobile  : 00919885220558.=
*



<https://www.avast.com/sig-email?utm_medium=3Demail&utm_source=3Dlink&utm_c=
ampaign=3Dsig-email&utm_content=3Dwebmail>
Virus-free.
www.avast.com
<https://www.avast.com/sig-email?utm_medium=3Demail&utm_source=3Dlink&utm_c=
ampaign=3Dsig-email&utm_content=3Dwebmail>
<#m_-413645396344358061_m_1144614612318168045_m_-2770182790619795747_m_-175=
7954985685463862_m_2632701677364239479_m_-7859414300626544545_m_89732414859=
72011198_m_1650279839983090334_m_-3859158165206963548_m_-405681073214480716=
9_m_-5134999211326095422_m_-3654623680604236362_m_4883785113315603380_m_-62=
94982917282084914_m_8260029735099100549_m_-1520348231714070133_m_-750850152=
0517816520_m_-5442927633578215405_m_-8373588021617490625_m_9467152927936131=
69_m_-5521316931868309007_m_-4937890955760788213_m_5683831117556876113_m_-8=
139928339925987547_m_-3403615867946401255_m_8751772714837796726_m_909883855=
4465746435_m_-3282444246998332795_m_7937977968340582098_m_-1149840621899385=
680_m_1651331605730147934_m_7595420528158243629_m_3152544239260371747_m_-60=
66361559085936680_m_6198841603324961225_m_-3114899299160602992_m_3347026024=
856606078_m_-7490993244583202227_m_-5792123506588379785_m_43177945928432390=
38_m_-3504423347621338573_m_3985833348117314351_m_-3416787278026935072_m_70=
27784573079824898_m_5318402907825611057_m_-7146247180907532732_m_1074080766=
030452405_m_-7496452618508741142_m_8559221723366034203_m_-24274506007319511=
50_m_6216660017293845822_m_7567346942303618238_m_-5759901322844954704_m_624=
1547928117865227_m_7422649327190993686_m_-2850426988067128790_m_-4907333050=
458995633_m_-1009086145171601619_m_-8207175106249958482_DAB4FAD8-2DD7-40BB-=
A1B8-4E2AA1F9FDF2>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAL0618sEcGAFPB7Nvx_eUn9oYZTHGcxyLdoQ-oTrEfejjNsEDQ%40mail.gmail.=
com.

--0000000000003ad84705d273839f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div class=3D"gmail_quote"><br><div dir=3D"ltr"><div class=
=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"lt=
r"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><=
div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"g=
mail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><d=
iv class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div d=
ir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_=
quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div cl=
ass=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D=
"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote=
"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=
=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"lt=
r"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><=
div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"g=
mail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><d=
iv class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div d=
ir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_=
quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div cl=
ass=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D=
"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote=
"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=
=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"lt=
r"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><=
div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"g=
mail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><d=
iv class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div d=
ir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_=
quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div cl=
ass=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D=
"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote=
"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=
=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"lt=
r"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><=
div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"g=
mail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><d=
iv class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div d=
ir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_=
quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div cl=
ass=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D=
"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote=
"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=
=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"lt=
r"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><=
div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"g=
mail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><d=
iv class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr"><br></div><d=
iv dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gm=
ail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><di=
v class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div di=
r=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_q=
uote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div cla=
ss=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"=
ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"=
><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr"><div class=3D=
"gmail_quote"><div dir=3D"ltr"><div class=3D"gmail_quote"><div dir=3D"ltr">=
<div class=3D"gmail_quote"><div dir=3D"ltr"><p class=3D"MsoNormal" style=3D=
"margin:0in 0in 0.0001pt 5.05pt;font-size:11pt;font-family:Calibri,sans-ser=
if"><span style=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,s=
erif"><b>SHAIK</b></span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif"><b>=C2=A0</b></span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif"><b>Mobile=C2=A0
:=C2=A0=C2=A0 00919885220558.</b></span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:5pt;font-family=
:&quot;Times New Roman&quot;,serif"><b>=C2=A0</b></span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif"><b>Email=C2=A0=C2=A0=C2=A0
:=C2=A0=C2=A0 <a href=3D"mailto:shaik.karemullah@rediffmail.com" target=3D"=
_blank">shaik.karemullah@rediffmail.com</a></b></span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif"><b>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 <a href=3D"mailto:safetyo=
fficer67@yahoo.in" target=3D"_blank">safetyofficer67@yahoo.in</a></b></span=
></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 </span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">Respected sir,</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif"><b>Fire &amp; Safety Officer /QHSE Hea=
lth
Safety &amp; Environment Officer</b> caught my attention as it seems an ide=
al match
for my experience and talents. As a capable health and safety professional =
with
a solid technical background and a wide range of experience, I believe I am
someone who will be an asset to your company. With a proven ability to
implement health and safety initiatives that get results, I would like to
explore the possibility of putting my skills and experience to work for you=
. </span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">Quality Co-coordinator to ensure that
all health and safety procedures are carried out correctly according to loc=
al,
national and international legislation. This role usually involves attendin=
g
external QHSE meetings as the company=E2=80=99s representative.</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">(QHSE) Safety Officer is responsible f=
or
all documentation in relation to health and safety and you will be required=
 to
keep all documentation and safety manuals up to date and distribute
appropriately within the organization.</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">I would be pleased to have the
opportunity to discuss future employment and look forward to speaking with =
you.
Feel free to contact me at the address and phone number listed below.</span=
></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">Joining period=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 :=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Immediately.</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">Present location=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 :=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 INDIA.</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">Thank you for your consideration.</spa=
n></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">Sincerely,</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">SHAIK</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif">=C2=A0</span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:12pt;font-famil=
y:&quot;Times New Roman&quot;,serif"><b>Please contact by Whatapp, Skype, I=
MO,
Viber and Mobile=C2=A0 : 00919885220558.</b></span></p>

<p class=3D"MsoNormal" style=3D"margin:0in 0in 0.0001pt 5.05pt;font-size:11=
pt;font-family:Calibri,sans-serif"><span style=3D"font-size:14pt;font-famil=
y:Arial,sans-serif">=C2=A0</span></p></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div><div id=3D"m_-413645396344358061m_1144614612318168045m_-2770182=
790619795747m_-1757954985685463862m_2632701677364239479m_-78594143006265445=
45m_8973241485972011198m_1650279839983090334m_-3859158165206963548m_-405681=
0732144807169m_-5134999211326095422m_-3654623680604236362m_4883785113315603=
380m_-6294982917282084914m_8260029735099100549m_-1520348231714070133m_-7508=
501520517816520m_-5442927633578215405m_-8373588021617490625m_94671529279361=
3169m_-5521316931868309007m_-4937890955760788213m_5683831117556876113m_-813=
9928339925987547m_-3403615867946401255m_8751772714837796726m_90988385544657=
46435m_-3282444246998332795m_7937977968340582098m_-1149840621899385680m_165=
1331605730147934m_7595420528158243629m_3152544239260371747m_-60663615590859=
36680m_6198841603324961225m_-3114899299160602992m_3347026024856606078m_-749=
0993244583202227m_-5792123506588379785m_4317794592843239038m_-3504423347621=
338573m_3985833348117314351m_-3416787278026935072m_7027784573079824898m_531=
8402907825611057m_-7146247180907532732m_1074080766030452405m_-7496452618508=
741142m_8559221723366034203m_-2427450600731951150m_6216660017293845822m_756=
7346942303618238m_-5759901322844954704m_6241547928117865227m_74226493271909=
93686m_-2850426988067128790m_-4907333050458995633m_-1009086145171601619m_-8=
207175106249958482DAB4FAD8-2DD7-40BB-A1B8-4E2AA1F9FDF2"><br>
<table style=3D"border-top:1px solid #d3d4de">
	<tbody><tr>
        <td style=3D"width:55px;padding-top:13px"><a href=3D"https://www.av=
ast.com/sig-email?utm_medium=3Demail&amp;utm_source=3Dlink&amp;utm_campaign=
=3Dsig-email&amp;utm_content=3Dwebmail" target=3D"_blank"><img src=3D"https=
://ipmcdn.avast.com/images/icons/icon-envelope-tick-round-orange-animated-n=
o-repeat-v1.gif" alt=3D"" width=3D"46" height=3D"29" style=3D"width:46px;he=
ight:29px"></a></td>
		<td style=3D"width:470px;padding-top:12px;color:#41424e;font-size:13px;fo=
nt-family:Arial,Helvetica,sans-serif;line-height:18px">Virus-free. <a href=
=3D"https://www.avast.com/sig-email?utm_medium=3Demail&amp;utm_source=3Dlin=
k&amp;utm_campaign=3Dsig-email&amp;utm_content=3Dwebmail" style=3D"color:#4=
453ea" target=3D"_blank">www.avast.com</a>
		</td>
	</tr>
</tbody></table><a href=3D"#m_-413645396344358061_m_1144614612318168045_m_-=
2770182790619795747_m_-1757954985685463862_m_2632701677364239479_m_-7859414=
300626544545_m_8973241485972011198_m_1650279839983090334_m_-385915816520696=
3548_m_-4056810732144807169_m_-5134999211326095422_m_-3654623680604236362_m=
_4883785113315603380_m_-6294982917282084914_m_8260029735099100549_m_-152034=
8231714070133_m_-7508501520517816520_m_-5442927633578215405_m_-837358802161=
7490625_m_946715292793613169_m_-5521316931868309007_m_-4937890955760788213_=
m_5683831117556876113_m_-8139928339925987547_m_-3403615867946401255_m_87517=
72714837796726_m_9098838554465746435_m_-3282444246998332795_m_7937977968340=
582098_m_-1149840621899385680_m_1651331605730147934_m_7595420528158243629_m=
_3152544239260371747_m_-6066361559085936680_m_6198841603324961225_m_-311489=
9299160602992_m_3347026024856606078_m_-7490993244583202227_m_-5792123506588=
379785_m_4317794592843239038_m_-3504423347621338573_m_3985833348117314351_m=
_-3416787278026935072_m_7027784573079824898_m_5318402907825611057_m_-714624=
7180907532732_m_1074080766030452405_m_-7496452618508741142_m_85592217233660=
34203_m_-2427450600731951150_m_6216660017293845822_m_7567346942303618238_m_=
-5759901322844954704_m_6241547928117865227_m_7422649327190993686_m_-2850426=
988067128790_m_-4907333050458995633_m_-1009086145171601619_m_-8207175106249=
958482_DAB4FAD8-2DD7-40BB-A1B8-4E2AA1F9FDF2" width=3D"1" height=3D"1"></a><=
/div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>
</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAL0618sEcGAFPB7Nvx_eUn9oYZTHGcxyLdoQ-oTrEfejjNsEDQ%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAL0618sEcGAFPB7Nvx_eUn9oYZTHGcxyLdoQ-oTrEfejjNsEDQ=
%40mail.gmail.com</a>.<br />

--0000000000003ad84705d273839f--
